import SmzaRp05TypedRelation
import HegemonCrypto.SmallWoodV8Smz9SemanticCanonicalWitness
import HegemonCrypto.SmallWoodV8Smz9SemanticDenseRange

/-!
# RP05 finite CSR authorization-source bridge

The first section is deliberately only a generic copy lemma: its word names
do not fix coordinates.  The current-RP05 sections below fix calls, lanes,
public projections, witness rows, padding, frame constants, and digest-copy
coordinates before deriving the typed projection from `AcceptsPacked`.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05AuthSourceBridge

open Hegemon.Transaction.Poseidon2V8RelationProgram
open Hegemon.Transaction.Poseidon2V8DecoderRefinement
  (rawIndex hashInitialIndex hashFinalIndex)
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.V8Smz9SemanticCanonicalWitness
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open SmzaRp05TypedRelation
open SmzaRp05ThresholdHistory
open SmzaRp05ThresholdRegistry
open Hegemon.Transaction.Poseidon2V8SemanticSpecification

set_option autoImplicit false
open scoped Classical

/-- All source words required by the local AUTH/registry projection. -/
inductive AuthSourceWord where
  | intent (word : Fin 104)
  | policy (word : Fin 44)
  | intentDigest (limb : Fin 7)
  | policyDigest (limb : Fin 7)
  | policyDigestHash (limb : Fin 7)
  | nextAccumulatorDigest (limb : Fin 7)
  | valueLockDigest (limb : Fin 7)
  | currentAccumulator (word : Fin 23)
  | nextAccumulator (word : Fin 23)
  | boundCurrent (limb : Fin 7)
  | boundSecondary (limb : Fin 7)
  | inputNoteIdentity (input : Fin 2) (limb : Fin 7)
  | outputZeroIdentity (limb : Fin 7)
deriving DecidableEq

/-- Exact finite source artifact.  `attemptShape` fixes the raw CSR equation
to `source - target = 0`; `zero/one/negativeOne` are syntax-directed DAG
proofs.  There is no witness-semantic field. -/
structure AuthSourceCertificate (components : RelationProgramComponents) where
  csrCanonicalWithRows :
    ({ expressions := components.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical true
  zeroNode : Nat
  oneNode : Nat
  negativeOneNode : Nat
  zeroRealizes : Realizes components.csrExpressions zeroNode (.constant 0)
  oneRealizes : Realizes components.csrExpressions oneNode (.constant 1)
  negativeOneRealizes : Realizes components.csrExpressions negativeOneNode
    (.sub (.constant 0) (.constant 1))
  sourceIndex : AuthSourceWord → Nat
  targetIndex : AuthSourceWord → Nat
  attempt : AuthSourceWord → CsrExecutableAttempt
  attemptMember : ∀ word, attempt word ∈ components.csrAttempts
  attemptShape : ∀ word,
    (attempt word).terms =
      [(sourceIndex word, oneNode), (targetIndex word, negativeOneNode)] ∧
    (attempt word).targetRoot = zeroNode
  sourceBound : ∀ word,
    sourceIndex word < Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessWordCount
  targetBound : ∀ word,
    targetIndex word < Hegemon.Transaction.Poseidon2V8RelationProgram.packedWitnessWordCount

private theorem trace_node_value
    {components : RelationProgramComponents}
    (canonical :
      ({ expressions := components.csrExpressions, roots := [] } :
        ExpressionProgram).Canonical true)
    {publicWords values : List Nat}
    (evaluated : evalExpressionNodes publicWords [] components.csrExpressions =
      some values) {node : Nat} {term : SourceTerm}
    (realizes : Realizes components.csrExpressions node term) :
    (values.getD node 0 : Goldilocks) =
      term.eval (fun index => (publicWords.getD index 0 : Goldilocks))
        (fun _ => 0) := by
  have bound : node < components.csrExpressions.length := by
    induction realizes with
    | constant found =>
        exact (List.getElem?_eq_some_iff.mp found).1
    | publicInput found =>
        exact (List.getElem?_eq_some_iff.mp found).1
    | witness found =>
        exact (List.getElem?_eq_some_iff.mp found).1
    | add found _ _ _ _ _ _ =>
        exact (List.getElem?_eq_some_iff.mp found).1
    | sub found _ _ _ _ _ _ =>
        exact (List.getElem?_eq_some_iff.mp found).1
    | mul found _ _ _ _ _ _ =>
        exact (List.getElem?_eq_some_iff.mp found).1
  have refined := fieldAt_refines_source
    ({ expressions := components.csrExpressions, roots := [] } : ExpressionProgram)
    publicWords [] values canonical evaluated node bound
  rw [fieldAt_of_realizes realizes] at refined
  simpa using refined.symm

/-- One accepted current CSR program forces one actual packed source copy. -/
theorem accepted_auth_source_word
    {components : RelationProgramComponents}
    (certificate : AuthSourceCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (word : AuthSourceWord) :
    packed.getD (certificate.sourceIndex word) 0 =
      packed.getD (certificate.targetIndex word) 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have zeroValue : (values.getD certificate.zeroNode 0 : Goldilocks) = 0 := by
    simpa [SourceTerm.eval] using
      trace_node_value certificate.csrCanonicalWithRows evaluated certificate.zeroRealizes
  have oneValue : (values.getD certificate.oneNode 0 : Goldilocks) = 1 := by
    simpa [SourceTerm.eval] using
      trace_node_value certificate.csrCanonicalWithRows evaluated certificate.oneRealizes
  have negativeOneValue :
      (values.getD certificate.negativeOneNode 0 : Goldilocks) = -1 := by
    simpa [SourceTerm.eval] using
      trace_node_value certificate.csrCanonicalWithRows evaluated certificate.negativeOneRealizes
  have equation := accepted_csr_attempt_field_equality
    (attempts (certificate.attempt word) (certificate.attemptMember word))
  rw [(certificate.attemptShape word).1, (certificate.attemptShape word).2] at equation
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, oneValue, negativeOneValue, zeroValue, one_mul,
    neg_one_mul, add_zero] at equation
  have fieldEquality :
      (packed.getD (certificate.sourceIndex word) 0 : Goldilocks) =
      (packed.getD (certificate.targetIndex word) 0 : Goldilocks) := by
    linear_combination equation
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 (certificate.sourceIndex word))
    (packed_word_canonical accepted.2.1 (certificate.targetIndex word))
    fieldEquality

def sourceWords {components : RelationProgramComponents}
    (certificate : AuthSourceCertificate components)
    (packed : List Nat) (words : List AuthSourceWord) : List Nat :=
  words.map fun word => packed.getD (certificate.sourceIndex word) 0

def targetWords {components : RelationProgramComponents}
    (certificate : AuthSourceCertificate components)
    (packed : List Nat) (words : List AuthSourceWord) : List Nat :=
  words.map fun word => packed.getD (certificate.targetIndex word) 0

theorem accepted_auth_source_words
    {components : RelationProgramComponents}
    (certificate : AuthSourceCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (words : List AuthSourceWord) :
    sourceWords certificate packed words = targetWords certificate packed words := by
  apply List.map_congr_left
  intro word _
  exact accepted_auth_source_word certificate accepted word

def intentWords : List AuthSourceWord :=
  List.ofFn fun word : Fin 104 => .intent word

def policyWords : List AuthSourceWord :=
  List.ofFn fun word : Fin 44 => .policy word

def policyDigestWords : List AuthSourceWord :=
  List.ofFn fun limb : Fin 7 => .policyDigest limb

def currentAccumulatorWords : List AuthSourceWord :=
  List.ofFn fun word : Fin 23 => .currentAccumulator word

def nextAccumulatorWords : List AuthSourceWord :=
  List.ofFn fun word : Fin 23 => .nextAccumulator word

def boundCurrentWords : List AuthSourceWord :=
  List.ofFn fun limb : Fin 7 => .boundCurrent limb

def boundSecondaryWords : List AuthSourceWord :=
  List.ofFn fun limb : Fin 7 => .boundSecondary limb

def inputNoteIdentityWords (input : Fin 2) : List AuthSourceWord :=
  List.ofFn fun limb : Fin 7 => .inputNoteIdentity input limb

def outputZeroIdentityWords : List AuthSourceWord :=
  List.ofFn fun limb : Fin 7 => .outputZeroIdentity limb

/-- Exact successful projection consumed by the registry codec. -/
structure GenericCopyProjection {components : RelationProgramComponents}
    (certificate : AuthSourceCertificate components)
    (packed : List Nat) : Prop where
  intent : sourceWords certificate packed intentWords =
    targetWords certificate packed intentWords
  policy : sourceWords certificate packed policyWords =
    targetWords certificate packed policyWords
  policyDigest : sourceWords certificate packed policyDigestWords =
    targetWords certificate packed policyDigestWords
  currentAccumulator : sourceWords certificate packed currentAccumulatorWords =
    targetWords certificate packed currentAccumulatorWords
  nextAccumulator : sourceWords certificate packed nextAccumulatorWords =
    targetWords certificate packed nextAccumulatorWords
  boundCurrent : sourceWords certificate packed boundCurrentWords =
    targetWords certificate packed boundCurrentWords
  boundSecondary : sourceWords certificate packed boundSecondaryWords =
    targetWords certificate packed boundSecondaryWords
  inputNoteIdentity : ∀ input : Fin 2,
    sourceWords certificate packed (inputNoteIdentityWords input) =
      targetWords certificate packed (inputNoteIdentityWords input)
  outputZeroIdentity : sourceWords certificate packed outputZeroIdentityWords =
    targetWords certificate packed outputZeroIdentityWords

theorem packed_program_implies_auth_source_projection
    {components : RelationProgramComponents}
    (certificate : AuthSourceCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    GenericCopyProjection certificate packed where
  intent := accepted_auth_source_words certificate accepted intentWords
  policy := accepted_auth_source_words certificate accepted policyWords
  policyDigest := accepted_auth_source_words certificate accepted policyDigestWords
  currentAccumulator := accepted_auth_source_words certificate accepted currentAccumulatorWords
  nextAccumulator := accepted_auth_source_words certificate accepted nextAccumulatorWords
  boundCurrent := accepted_auth_source_words certificate accepted boundCurrentWords
  boundSecondary := accepted_auth_source_words certificate accepted boundSecondaryWords
  inputNoteIdentity input :=
    accepted_auth_source_words certificate accepted (inputNoteIdentityWords input)
  outputZeroIdentity :=
    accepted_auth_source_words certificate accepted outputZeroIdentityWords

/-- The two finite generated certificates needed for the current local
registry/AUTH refinement. -/
structure GenericTypedCertificate
    (components : RelationProgramComponents) where
  nonlinear : CurrentLocalArtifactCertificate components
  csr : AuthSourceCertificate components

structure GenericTypedProjection
    {components : RelationProgramComponents}
    (certificate : GenericTypedCertificate components)
    (publicWords packed : List Nat) : Prop where
  laneSemantics : ∀ lane : Fin 64,
    LocalSemanticRelation publicWords
      (packedWitnessLaneRows packed lane.val)
  authSources : GenericCopyProjection certificate.csr packed

/-- `R_prog => R_sem(projectRP05)` for the bounded AUTH/registry surface.
All premises are program acceptance plus finite syntactic source artifacts. -/
theorem packed_program_implies_generic_typed_projection
    {components : RelationProgramComponents}
    (certificate : GenericTypedCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    GenericTypedProjection certificate publicWords packed where
  laneSemantics lane :=
    packed_program_implies_local_semantics certificate.nonlinear accepted lane
  authSources :=
    packed_program_implies_auth_source_projection certificate.csr accepted

/-! ## Fixed current RP05 absorbed-word semantics -/

def intentOriginalIndex (word : Fin 104) : Nat :=
  if word.val < 4 then word.val
  else if word.val < 33 then word.val + 14
  else word.val + 16

def intentForcedZero (word : Fin 104) : Prop :=
  let source := intentOriginalIndex word
  (49 ≤ source ∧ source < 54) ∨ (87 ≤ source ∧ source < 94) ∨
    (113 ≤ source ∧ source < 120)

instance (word : Fin 104) : Decidable (intentForcedZero word) := by
  unfold intentForcedZero
  infer_instance

def absorbedWord (packed : List Nat) (firstCall word : Nat) : Goldilocks :=
  let block := word / 8
  let lane := word % 8
  (packed.getD (hashInitialIndex (firstCall + block) lane) 0 : Goldilocks) -
    if block = 0 then 0
    else (packed.getD (hashFinalIndex (firstCall + block - 1) lane) 0 : Goldilocks)

def intentTarget (publicWords : List Nat) (word : Fin 104) : Goldilocks :=
  if intentForcedZero word then 0
  else (publicWords.getD (intentOriginalIndex word) 0 : Goldilocks)

inductive WitnessAbsorbWord where
  | policy (word : Fin 44)
  | currentAccumulator (word : Fin 23)
  | nextAccumulator (word : Fin 23)
deriving DecidableEq

def WitnessAbsorbWord.firstCall : WitnessAbsorbWord → Nat
  | .policy _ => 94
  | .currentAccumulator _ => 100
  | .nextAccumulator _ => 103

def WitnessAbsorbWord.word : WitnessAbsorbWord → Nat
  | .policy word | .currentAccumulator word | .nextAccumulator word => word.val

/-- Fixed target coordinates from the current 139-row AUTH layout. -/
def WitnessAbsorbWord.targetIndex : WitnessAbsorbWord → Nat
  | .policy word =>
      if word.val = 0 then rawIndex 136
      else if word.val = 1 then rawIndex 137
      else
        let tagWord := word.val - 2
        rawIndex (164 + tagWord)
  | .currentAccumulator word =>
      if word.val < 7 then rawIndex (122 + word.val)
      else if word.val < 14 then rawIndex (129 + word.val - 7)
      else if word.val = 14 then rawIndex 136
      else if word.val = 15 then rawIndex 137
      else if word.val = 16 then rawIndex 138
      else rawIndex (139 + word.val - 17)
  | .nextAccumulator word =>
      if word.val < 7 then rawIndex (122 + word.val)
      else if word.val < 14 then rawIndex (129 + word.val - 7)
      else if word.val = 14 then rawIndex 136
      else if word.val = 15 then rawIndex 137
      else if word.val = 16 then rawIndex 145
      else rawIndex (146 + word.val - 17)

/-! The declared absorbed words are not the whole sponge initialization.
The same CSR family also fixes every rate-padding cell and all capacity/frame
cells.  These definitions name that finite surface without leaving call,
block, lane, domain, or length to a generated artifact. -/

inductive CurrentSpongeFamily where
  | intent | policy | currentAccumulator | nextAccumulator
deriving DecidableEq

def CurrentSpongeFamily.firstCall : CurrentSpongeFamily → Nat
  | .intent => 81
  | .policy => 94
  | .currentAccumulator => 100
  | .nextAccumulator => 103

def CurrentSpongeFamily.wordCount : CurrentSpongeFamily → Nat
  | .intent => 104
  | .policy => 44
  | .currentAccumulator | .nextAccumulator => 23

def CurrentSpongeFamily.blockCount : CurrentSpongeFamily → Nat
  | .intent => 13
  | .policy => 6
  | .currentAccumulator | .nextAccumulator => 3

def CurrentSpongeFamily.domain : CurrentSpongeFamily → Nat
  | .intent => 0x4854_5838_494e_5401
  | .policy => 0x4841_5038_504f_4c01
  | .currentAccumulator | .nextAccumulator => 6

def spongeModeMarker : Nat := 0x5350_4f4e_4745_5631
def suiteMarker : Nat := 0x4845_475f_5032_3136

/-- Exactly the cells not supplied by a declared absorbed word: capacity
lanes and the tail rate padding of a non-full final block. -/
structure CurrentFrameWord where
  family : CurrentSpongeFamily
  block : Nat
  lane : Fin 16
  blockBound : block < family.blockCount
  isFrame : 8 ≤ lane.val ∨ family.wordCount ≤ block * 8 + lane.val
deriving DecidableEq

def CurrentFrameWord.expected (word : CurrentFrameWord) : Nat :=
  if word.block = 0 then
    if word.lane.val = 8 then word.family.domain
    else if word.lane.val = 9 then word.family.wordCount
    else if word.lane.val = 10 then spongeModeMarker
    else if word.lane.val = 11 ∧ word.family.blockCount = 1 then 1
    else if word.lane.val = 15 then suiteMarker
    else 0
  else if word.lane.val = 11 ∧ word.block + 1 = word.family.blockCount then 1
  else 0

def CurrentFrameWord.difference (word : CurrentFrameWord)
    (packed : List Nat) : Goldilocks :=
  let call := word.family.firstCall + word.block
  (packed.getD (hashInitialIndex call word.lane.val) 0 : Goldilocks) -
    if word.block = 0 then 0
    else (packed.getD (hashFinalIndex (call - 1) word.lane.val) 0 : Goldilocks)

/-- Finite certificate for `bind_sponge`'s padding and frame attempts.  The
target expression is fixed to the source-level constant computed above. -/
structure CurrentFrameCertificate (components : RelationProgramComponents) where
  csrCanonicalWithRows :
    ({ expressions := components.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical true
  oneNode : Nat
  negativeOneNode : Nat
  oneRealizes : Realizes components.csrExpressions oneNode (.constant 1)
  negativeOneRealizes : Realizes components.csrExpressions negativeOneNode
    (.sub (.constant 0) (.constant 1))
  constantNode : CurrentFrameWord → Nat
  constantRealizes : ∀ word, Realizes components.csrExpressions
    (constantNode word) (.constant word.expected)
  attempt : CurrentFrameWord → CsrExecutableAttempt
  attemptMember : ∀ word, attempt word ∈ components.csrAttempts
  attemptTerms : ∀ word,
    (attempt word).terms =
      if word.block = 0 then
        [(hashInitialIndex word.family.firstCall word.lane.val, oneNode)]
      else
        [(hashInitialIndex (word.family.firstCall + word.block) word.lane.val, oneNode),
          (hashFinalIndex (word.family.firstCall + word.block - 1) word.lane.val,
            negativeOneNode)]
  attemptTarget : ∀ word, (attempt word).targetRoot = constantNode word

theorem accepted_current_frame_word
    {components : RelationProgramComponents}
    (certificate : CurrentFrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (word : CurrentFrameWord) :
    word.difference packed = (word.expected : Goldilocks) := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have one : (values.getD certificate.oneNode 0 : Goldilocks) = 1 := by
    simpa [SourceTerm.eval] using trace_node_value
      certificate.csrCanonicalWithRows evaluated certificate.oneRealizes
  have negative :
      (values.getD certificate.negativeOneNode 0 : Goldilocks) = -1 := by
    simpa [SourceTerm.eval] using trace_node_value
      certificate.csrCanonicalWithRows evaluated certificate.negativeOneRealizes
  have constant :
      (values.getD (certificate.constantNode word) 0 : Goldilocks) = word.expected := by
    simpa [SourceTerm.eval] using trace_node_value
      certificate.csrCanonicalWithRows evaluated (certificate.constantRealizes word)
  have equation := accepted_csr_attempt_field_equality
    (attempts (certificate.attempt word) (certificate.attemptMember word))
  rw [certificate.attemptTerms word, certificate.attemptTarget word] at equation
  by_cases first : word.block = 0
  · rw [if_pos first] at equation
    simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
      List.sum_nil] at equation
    rw [one, constant] at equation
    simpa [CurrentFrameWord.difference, first] using equation
  · rw [if_neg first] at equation
    simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
      List.sum_nil] at equation
    rw [one, negative, constant] at equation
    simpa [CurrentFrameWord.difference, first, sub_eq_add_neg] using equation

structure CurrentAbsorbCertificate (components : RelationProgramComponents) where
  csrCanonicalWithRows :
    ({ expressions := components.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical true
  zeroNode : Nat
  oneNode : Nat
  negativeOneNode : Nat
  zeroRealizes : Realizes components.csrExpressions zeroNode (.constant 0)
  oneRealizes : Realizes components.csrExpressions oneNode (.constant 1)
  negativeOneRealizes : Realizes components.csrExpressions negativeOneNode
    (.sub (.constant 0) (.constant 1))
  publicNode : Fin 120 → Nat
  publicRealizes : ∀ word, Realizes components.csrExpressions (publicNode word)
    (.publicInput word.val)
  intentAttempt : Fin 104 → CsrExecutableAttempt
  intentMember : ∀ word, intentAttempt word ∈ components.csrAttempts
  intentTerms : ∀ word,
    (intentAttempt word).terms =
      if word.val / 8 = 0 then
        [(hashInitialIndex (81 + word.val / 8) (word.val % 8), oneNode)]
      else
        [(hashInitialIndex (81 + word.val / 8) (word.val % 8), oneNode),
          (hashFinalIndex (81 + word.val / 8 - 1) (word.val % 8), negativeOneNode)]
  intentTarget : ∀ word,
    (intentAttempt word).targetRoot =
      if intentForcedZero word then zeroNode
      else publicNode ⟨intentOriginalIndex word, by
        have wordBound := word.isLt
        unfold intentOriginalIndex
        split
        · omega
        · split <;> omega⟩
  witnessAttempt : WitnessAbsorbWord → CsrExecutableAttempt
  witnessMember : ∀ word, witnessAttempt word ∈ components.csrAttempts
  witnessTerms : ∀ word,
    (witnessAttempt word).terms =
      if word.word / 8 = 0 then
        [(hashInitialIndex word.firstCall (word.word % 8), oneNode),
          (word.targetIndex, negativeOneNode)]
      else
        [(hashInitialIndex (word.firstCall + word.word / 8) (word.word % 8), oneNode),
          (hashFinalIndex (word.firstCall + word.word / 8 - 1)
            (word.word % 8), negativeOneNode),
          (word.targetIndex, negativeOneNode)]
  witnessTarget : ∀ word, (witnessAttempt word).targetRoot = zeroNode

private theorem current_trace_constants
    {components : RelationProgramComponents}
    (certificate : CurrentAbsorbCertificate components)
    {publicWords values : List Nat}
    (evaluated : evalExpressionNodes publicWords [] components.csrExpressions = some values) :
    (values.getD certificate.zeroNode 0 : Goldilocks) = 0 ∧
    (values.getD certificate.oneNode 0 : Goldilocks) = 1 ∧
    (values.getD certificate.negativeOneNode 0 : Goldilocks) = -1 := by
  have zero := trace_node_value certificate.csrCanonicalWithRows evaluated
    certificate.zeroRealizes
  have one := trace_node_value certificate.csrCanonicalWithRows evaluated
    certificate.oneRealizes
  have negative := trace_node_value certificate.csrCanonicalWithRows evaluated
    certificate.negativeOneRealizes
  simpa [SourceTerm.eval] using And.intro zero (And.intro one negative)

theorem accepted_current_intent_word
    {components : RelationProgramComponents}
    (certificate : CurrentAbsorbCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (word : Fin 104) :
    absorbedWord packed 81 word.val = intentTarget publicWords word := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  obtain ⟨zero, one, negative⟩ := current_trace_constants certificate evaluated
  have equation := accepted_csr_attempt_field_equality
    (attempts (certificate.intentAttempt word) (certificate.intentMember word))
  rw [certificate.intentTerms word, certificate.intentTarget word] at equation
  have publicValue :
      (values.getD (certificate.publicNode
        ⟨intentOriginalIndex word, by
          have wordBound := word.isLt
          unfold intentOriginalIndex
          split
          · omega
          · split <;> omega⟩) 0 : Goldilocks) =
        (publicWords.getD (intentOriginalIndex word) 0 : Goldilocks) := by
    simpa [SourceTerm.eval] using trace_node_value
      certificate.csrCanonicalWithRows evaluated
      (certificate.publicRealizes
        ⟨intentOriginalIndex word, by
          have wordBound := word.isLt
          unfold intentOriginalIndex
          split
          · omega
          · split <;> omega⟩)
  by_cases first : word.val / 8 = 0
  · by_cases forced : intentForcedZero word
    · simp only [if_pos first, if_pos forced, csrFieldSum,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at equation
      rw [one, zero] at equation
      rw [first] at equation
      simp only [one_mul, add_zero] at equation
      simp [absorbedWord, intentTarget, first, forced]
      simpa only [List.getD_eq_getElem?_getD, add_zero] using equation
    · simp only [if_pos first, if_neg forced, csrFieldSum,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at equation
      rw [one, publicValue] at equation
      rw [first] at equation
      simp only [one_mul, add_zero] at equation
      simp [absorbedWord, intentTarget, first, forced]
      simpa only [List.getD_eq_getElem?_getD, add_zero] using equation
  · by_cases forced : intentForcedZero word
    · simp only [if_neg first, if_pos forced, csrFieldSum,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at equation
      rw [one, negative, zero] at equation
      simp only [one_mul, neg_one_mul, add_zero] at equation
      have priorCall : 81 + word.val / 8 - 1 = 80 + word.val / 8 := by omega
      rw [priorCall] at equation
      simp [absorbedWord, intentTarget, first, forced, sub_eq_add_neg]
      simpa only [List.getD_eq_getElem?_getD, add_zero, sub_eq_add_neg] using equation
    · simp only [if_neg first, if_neg forced, csrFieldSum,
        List.map_cons, List.map_nil, List.sum_cons, List.sum_nil] at equation
      rw [one, negative, publicValue] at equation
      simp only [one_mul, neg_one_mul] at equation
      have priorCall : 81 + word.val / 8 - 1 = 80 + word.val / 8 := by omega
      rw [priorCall] at equation
      simp [absorbedWord, intentTarget, first, forced, sub_eq_add_neg]
      simpa only [List.getD_eq_getElem?_getD, add_zero, sub_eq_add_neg] using equation

theorem accepted_current_witness_absorb_word
    {components : RelationProgramComponents}
    (certificate : CurrentAbsorbCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (word : WitnessAbsorbWord) :
    absorbedWord packed word.firstCall word.word =
      (packed.getD word.targetIndex 0 : Goldilocks) := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  obtain ⟨zero, one, negative⟩ := current_trace_constants certificate evaluated
  have equation := accepted_csr_attempt_field_equality
    (attempts (certificate.witnessAttempt word) (certificate.witnessMember word))
  rw [certificate.witnessTerms word, certificate.witnessTarget word] at equation
  by_cases first : word.word / 8 = 0
  · simp only [if_pos first, csrFieldSum, List.map_cons, List.map_nil,
      List.sum_cons, List.sum_nil] at equation
    rw [one, negative, zero] at equation
    simp only [one_mul, neg_one_mul, add_zero] at equation
    have eq' : (packed.getD (hashInitialIndex word.firstCall (word.word % 8)) 0 : Goldilocks) -
        (packed.getD word.targetIndex 0 : Goldilocks) = 0 := by
      simpa only [sub_eq_add_neg] using equation
    have same := sub_eq_zero.mp eq'
    simpa [absorbedWord, first] using same
  · simp only [if_neg first, csrFieldSum, List.map_cons, List.map_nil,
      List.sum_cons, List.sum_nil] at equation
    rw [one, negative, zero] at equation
    simp only [one_mul, neg_one_mul, add_zero] at equation
    have eq' : (packed.getD
        (hashInitialIndex (word.firstCall + word.word / 8) (word.word % 8)) 0 : Goldilocks) -
        (packed.getD
          (hashFinalIndex (word.firstCall + word.word / 8 - 1) (word.word % 8)) 0 : Goldilocks) -
        (packed.getD word.targetIndex 0 : Goldilocks) = 0 := by
      simpa only [sub_eq_add_neg, add_assoc] using equation
    have same := sub_eq_zero.mp eq'
    simpa [absorbedWord, first, sub_eq_add_neg] using same

def currentIntentEncoding (publicWords : List Nat) : Fin 104 → Goldilocks :=
  fun word => intentTarget publicWords word

def absorbedIntentEncoding (packed : List Nat) : Fin 104 → Goldilocks :=
  fun word => absorbedWord packed 81 word.val

def absorbedPolicyEncoding (packed : List Nat) : Fin 44 → Goldilocks :=
  fun word => absorbedWord packed 94 word.val

def typedPolicyEncoding (packed : List Nat) : Fin 44 → Goldilocks :=
  fun word => (packed.getD (WitnessAbsorbWord.targetIndex (.policy word)) 0 : Goldilocks)

def absorbedCurrentAccumulator (packed : List Nat) : Fin 23 → Goldilocks :=
  fun word => absorbedWord packed 100 word.val

def typedCurrentAccumulator (packed : List Nat) : Fin 23 → Goldilocks :=
  fun word => (packed.getD
    (WitnessAbsorbWord.targetIndex (.currentAccumulator word)) 0 : Goldilocks)

def absorbedNextAccumulator (packed : List Nat) : Fin 23 → Goldilocks :=
  fun word => absorbedWord packed 103 word.val

def typedNextAccumulator (packed : List Nat) : Fin 23 → Goldilocks :=
  fun word => (packed.getD
    (WitnessAbsorbWord.targetIndex (.nextAccumulator word)) 0 : Goldilocks)

/-! ## Canonical accumulator-opening codec

This is the unhashed 23-word preimage carried separately from a note opening
and from the seven-word full-authorization preimage. -/

abbrev Accumulator23Words := Fin 23 → Nat

def accumulator23Policy (words : Accumulator23Words) : Fin 7 → Nat :=
  fun limb => words ⟨limb.val, by omega⟩

def accumulator23Intent (words : Accumulator23Words) : Fin 7 → Nat :=
  fun limb => words ⟨7 + limb.val, by omega⟩

def accumulator23Threshold (words : Accumulator23Words) : Nat := words 14
def accumulator23SignerCount (words : Accumulator23Words) : Nat := words 15

def accumulator23State (words : Accumulator23Words) : ApprovalState where
  count := words 16
  bitmap := Finset.univ.filter fun slot : SignerSlot => words ⟨17 + slot.val, by omega⟩ = 1

def encodeAccumulator23 (policy intent : Fin 7 → Nat)
    (threshold signerCount : Nat) (state : ApprovalState) : Accumulator23Words :=
  fun word =>
    if h0 : word.val < 7 then policy ⟨word.val, h0⟩
    else if h1 : word.val < 14 then intent ⟨word.val - 7, by omega⟩
    else if word.val = 14 then threshold
    else if word.val = 15 then signerCount
    else if word.val = 16 then state.count
    else if (⟨word.val - 17, by omega⟩ : SignerSlot) ∈ state.bitmap then 1 else 0

structure CanonicalAccumulator23 (words : Accumulator23Words) : Prop where
  thresholdRange : accumulator23Threshold words ≤ 6
  signerCountRange : accumulator23SignerCount words ≤ 6
  countRange : (accumulator23State words).count ≤ 6
  bitmapWordsBoolean : ∀ slot : SignerSlot,
    words ⟨17 + slot.val, by omega⟩ = 0 ∨
      words ⟨17 + slot.val, by omega⟩ = 1
  weight : (accumulator23State words).bitmap.card =
    (accumulator23State words).count

theorem accumulator23_decode_encode_state
    (policy intent : Fin 7 → Nat) (threshold signerCount : Nat)
    (state : ApprovalState) :
    accumulator23State
      (encodeAccumulator23 policy intent threshold signerCount state) = state := by
  cases state with
  | mk count bitmap =>
    simp only [accumulator23State, ApprovalState.mk.injEq]
    constructor
    · simp [encodeAccumulator23]
    · apply Finset.ext
      intro slot
      have h0 : ¬ 17 + slot.val < 7 := by omega
      have h1 : ¬ 17 + slot.val < 14 := by omega
      have h14 : 17 + slot.val ≠ 14 := by omega
      have h15 : 17 + slot.val ≠ 15 := by omega
      have h16 : 17 + slot.val ≠ 16 := by omega
      simp [encodeAccumulator23, h0, h1, h14, h15, h16]

theorem accumulator23_decode_encode_policy
    (policy intent : Fin 7 → Nat) (threshold signerCount : Nat)
    (state : ApprovalState) :
    accumulator23Policy
      (encodeAccumulator23 policy intent threshold signerCount state) = policy := by
  funext limb
  simp [accumulator23Policy, encodeAccumulator23]

theorem accumulator23_decode_encode_intent
    (policy intent : Fin 7 → Nat) (threshold signerCount : Nat)
    (state : ApprovalState) :
    accumulator23Intent
      (encodeAccumulator23 policy intent threshold signerCount state) = intent := by
  funext limb
  have belowSeven : ¬ 7 + limb.val < 7 := by omega
  have belowFourteen : 7 + limb.val < 14 := by omega
  simp [accumulator23Intent, encodeAccumulator23, belowSeven, belowFourteen]

theorem accumulator23_decode_encode_scalars
    (policy intent : Fin 7 → Nat) (threshold signerCount : Nat)
    (state : ApprovalState) :
    accumulator23Threshold
        (encodeAccumulator23 policy intent threshold signerCount state) = threshold ∧
      accumulator23SignerCount
        (encodeAccumulator23 policy intent threshold signerCount state) = signerCount := by
  simp [accumulator23Threshold, accumulator23SignerCount, encodeAccumulator23]

def typedCurrentAccumulatorWords (packed : List Nat) : Accumulator23Words :=
  fun word => packed.getD
    (WitnessAbsorbWord.targetIndex (.currentAccumulator word)) 0

def typedNextAccumulatorWords (packed : List Nat) : Accumulator23Words :=
  fun word => packed.getD
    (WitnessAbsorbWord.targetIndex (.nextAccumulator word)) 0

theorem typed_current_accumulator_is_cast_encoding (packed : List Nat) :
    typedCurrentAccumulator packed = fun word =>
      (typedCurrentAccumulatorWords packed word : Goldilocks) := by
  rfl

theorem typed_next_accumulator_is_cast_encoding (packed : List Nat) :
    typedNextAccumulator packed = fun word =>
      (typedNextAccumulatorWords packed word : Goldilocks) := by
  rfl

/-- Exact missing datum exposed by any attempt to construct the concrete
registry input for the current packed accumulator.  The record must provide
104 words whose live action-intent sponge equals the seven intent limbs stored
at raw rows129..135.  Approval mode does not obtain such words merely from
the stored digest. -/
theorem current_packed_accumulator_input_requires_intent_preimage
    {Policy Intent PolicyKey : Type*}
    {contextCodec : ContextCodec currentBindingModel Policy Intent PolicyKey}
    {expected : ChainContext Policy Intent PolicyKey}
    {current : ApprovalState} (packed : List Nat)
    (input : AccumulatorInput currentBindingModel currentOriginCodec
      contextCodec expected current)
    (openingExact : input.accumulatorOpening =
      CurrentBindingPreimage.accumulator (typedCurrentAccumulatorWords packed)) :
    ∃ preimage : CurrentIntentEncoding,
      poseidon2V8Sponge currentIntentBindingDomain (List.ofFn preimage) =
        List.ofFn (accumulator23Intent (typedCurrentAccumulatorWords packed)) := by
  obtain ⟨preimage, digest⟩ :=
    current_accumulator_input_supplies_intent_preimage input
  refine ⟨preimage, ?_⟩
  rw [openingExact] at digest
  change poseidon2V8Sponge currentIntentBindingDomain (List.ofFn preimage) =
    List.ofFn (accumulator23Intent (typedCurrentAccumulatorWords packed)) at digest
  exact digest

structure CurrentEncoderProjection (publicWords packed : List Nat) : Prop where
  intent : absorbedIntentEncoding packed = currentIntentEncoding publicWords
  policy : absorbedPolicyEncoding packed = typedPolicyEncoding packed
  currentAccumulator : absorbedCurrentAccumulator packed =
    typedCurrentAccumulator packed
  nextAccumulator : absorbedNextAccumulator packed = typedNextAccumulator packed

structure CurrentFrameProjection (packed : List Nat) : Prop where
  exact : ∀ word : CurrentFrameWord,
    word.difference packed = (word.expected : Goldilocks)

theorem packed_program_implies_current_encoder_projection
    {components : RelationProgramComponents}
    (certificate : CurrentAbsorbCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    CurrentEncoderProjection publicWords packed where
  intent := by
    funext word
    exact accepted_current_intent_word certificate accepted word
  policy := by
    funext word
    exact accepted_current_witness_absorb_word certificate accepted (.policy word)
  currentAccumulator := by
    funext word
    exact accepted_current_witness_absorb_word certificate accepted
      (.currentAccumulator word)
  nextAccumulator := by
    funext word
    exact accepted_current_witness_absorb_word certificate accepted
      (.nextAccumulator word)

theorem packed_program_implies_current_frame_projection
    {components : RelationProgramComponents}
    (certificate : CurrentFrameCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    CurrentFrameProjection packed where
  exact word := accepted_current_frame_word certificate accepted word

inductive CurrentDirectWord where
  | intentDigest (limb : Fin 7)
  | policyRaw (limb : Fin 7)
  | policyHash (limb : Fin 7)
  | nextAccumulatorDigest (limb : Fin 7)
  | valueLockDigest (limb : Fin 7)
  | boundCurrent (limb : Fin 7)
  | boundSecondary (limb : Fin 7)
deriving DecidableEq

def CurrentDirectWord.generic : CurrentDirectWord → AuthSourceWord
  | .intentDigest limb => .intentDigest limb
  | .policyRaw limb => .policyDigest limb
  | .policyHash limb => .policyDigestHash limb
  | .nextAccumulatorDigest limb => .nextAccumulatorDigest limb
  | .valueLockDigest limb => .valueLockDigest limb
  | .boundCurrent limb => .boundCurrent limb
  | .boundSecondary limb => .boundSecondary limb

def CurrentDirectWord.sourceIndex : CurrentDirectWord → Nat
  | .intentDigest limb => rawIndex (115 + limb.val)
  | .policyRaw limb => 280 * 64 + limb.val
  | .policyHash limb => 281 * 64 + limb.val
  | .nextAccumulatorDigest limb => 107 * 64 + limb.val
  | .valueLockDigest limb => 108 * 64 + limb.val
  | .boundCurrent limb => 110 * 64 + limb.val
  | .boundSecondary limb => 111 * 64 + limb.val

def CurrentDirectWord.targetIndex : CurrentDirectWord → Nat
  | .intentDigest limb => hashFinalIndex 93 limb.val
  | .policyRaw limb => rawIndex (122 + limb.val)
  | .policyHash limb => hashFinalIndex 99 limb.val
  | .nextAccumulatorDigest limb => hashFinalIndex 105 limb.val
  | .valueLockDigest limb => hashFinalIndex 106 limb.val
  | .boundCurrent limb => hashFinalIndex 107 limb.val
  | .boundSecondary limb => hashFinalIndex 108 limb.val

def CurrentDirectWord.minusOneNode (literal derived : Nat) : CurrentDirectWord → Nat
  | .policyRaw _ | .policyHash _ => derived
  | _ => literal

/-- The 49 actual direct-copy words are separate from absorbed sponge words.
Rust `csr.equality` emits a literal Goldilocks minus-one coefficient at CSR
node 3; the policy-inline `csr.bind` copies use the `0-1` expression at node
160. No generic `AuthSourceWord` selector can substitute another copy. -/
structure CurrentDirectCertificate (components : RelationProgramComponents) where
  csrCanonicalWithRows :
    ({ expressions := components.csrExpressions, roots := [] } :
      ExpressionProgram).Canonical true
  zeroNode : Nat
  oneNode : Nat
  literalMinusOneNode : Nat
  derivedMinusOneNode : Nat
  zeroRealizes : Realizes components.csrExpressions zeroNode (.constant 0)
  oneRealizes : Realizes components.csrExpressions oneNode (.constant 1)
  literalMinusOneRealizes : Realizes components.csrExpressions
    literalMinusOneNode (.constant 18446744069414584320)
  derivedMinusOneRealizes : Realizes components.csrExpressions
    derivedMinusOneNode (.sub (.constant 0) (.constant 1))
  attempt : CurrentDirectWord → CsrExecutableAttempt
  attemptMember : ∀ word, attempt word ∈ components.csrAttempts
  attemptTerms : ∀ word, (attempt word).terms =
    [(word.sourceIndex, oneNode),
      (word.targetIndex, word.minusOneNode literalMinusOneNode derivedMinusOneNode)]
  attemptTarget : ∀ word, (attempt word).targetRoot = zeroNode

theorem accepted_current_direct_word
    {components : RelationProgramComponents}
    (certificate : CurrentDirectCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (word : CurrentDirectWord) :
    packed.getD word.sourceIndex 0 = packed.getD word.targetIndex 0 := by
  obtain ⟨values, evaluated, attempts⟩ := accepted.2.2.2
  have zeroValue : (values.getD certificate.zeroNode 0 : Goldilocks) = 0 := by
    simpa [SourceTerm.eval] using
      trace_node_value certificate.csrCanonicalWithRows evaluated certificate.zeroRealizes
  have oneValue : (values.getD certificate.oneNode 0 : Goldilocks) = 1 := by
    simpa [SourceTerm.eval] using
      trace_node_value certificate.csrCanonicalWithRows evaluated certificate.oneRealizes
  have literalMinusOneValue :
      (values.getD certificate.literalMinusOneNode 0 : Goldilocks) = -1 := by
    have literal := trace_node_value certificate.csrCanonicalWithRows evaluated
      certificate.literalMinusOneRealizes
    have castMinusOne : (18446744069414584320 : Goldilocks) = -1 := by
      decide
    simpa [SourceTerm.eval, castMinusOne] using literal
  have derivedMinusOneValue :
      (values.getD certificate.derivedMinusOneNode 0 : Goldilocks) = -1 := by
    simpa [SourceTerm.eval] using
      trace_node_value certificate.csrCanonicalWithRows evaluated
        certificate.derivedMinusOneRealizes
  have minusOneValue :
      (values.getD
        (word.minusOneNode certificate.literalMinusOneNode certificate.derivedMinusOneNode)
        0 : Goldilocks) = -1 := by
    have literal' :
        (values[certificate.literalMinusOneNode]?.getD 0 : Goldilocks) = -1 := by
      simpa only [List.getD_eq_getElem?_getD] using literalMinusOneValue
    have derived' :
        (values[certificate.derivedMinusOneNode]?.getD 0 : Goldilocks) = -1 := by
      simpa only [List.getD_eq_getElem?_getD] using derivedMinusOneValue
    cases word <;> simp only [CurrentDirectWord.minusOneNode] <;> assumption
  have equation := accepted_csr_attempt_field_equality
    (attempts (certificate.attempt word) (certificate.attemptMember word))
  rw [certificate.attemptTerms word, certificate.attemptTarget word] at equation
  simp only [csrFieldSum, List.map_cons, List.map_nil, List.sum_cons,
    List.sum_nil, oneValue, minusOneValue, zeroValue, one_mul,
    neg_one_mul, add_zero] at equation
  have fieldEquality :
      (packed.getD word.sourceIndex 0 : Goldilocks) =
        (packed.getD word.targetIndex 0 : Goldilocks) := by
    linear_combination equation
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1 word.sourceIndex)
    (packed_word_canonical accepted.2.1 word.targetIndex)
    fieldEquality

structure CurrentDigestProjection (packed : List Nat) : Prop where
  intentDigest : ∀ limb : Fin 7,
    packed.getD (rawIndex (115 + limb.val)) 0 =
      packed.getD (hashFinalIndex 93 limb.val) 0
  policyRaw : ∀ limb : Fin 7,
    packed.getD (280 * 64 + limb.val) 0 =
      packed.getD (rawIndex (122 + limb.val)) 0
  policyHash : ∀ limb : Fin 7,
    packed.getD (281 * 64 + limb.val) 0 =
      packed.getD (hashFinalIndex 99 limb.val) 0
  nextAccumulatorDigest : ∀ limb : Fin 7,
    packed.getD (107 * 64 + limb.val) 0 =
      packed.getD (hashFinalIndex 105 limb.val) 0
  valueLockDigest : ∀ limb : Fin 7,
    packed.getD (108 * 64 + limb.val) 0 =
      packed.getD (hashFinalIndex 106 limb.val) 0
  boundCurrent : ∀ limb : Fin 7,
    packed.getD (110 * 64 + limb.val) 0 =
      packed.getD (hashFinalIndex 107 limb.val) 0
  boundSecondary : ∀ limb : Fin 7,
    packed.getD (111 * 64 + limb.val) 0 =
      packed.getD (hashFinalIndex 108 limb.val) 0

theorem packed_program_implies_current_digest_projection
    {components : RelationProgramComponents}
    (certificate : CurrentDirectCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    CurrentDigestProjection packed where
  intentDigest limb :=
    accepted_current_direct_word certificate accepted (.intentDigest limb)
  policyRaw limb := accepted_current_direct_word certificate accepted (.policyRaw limb)
  policyHash limb := accepted_current_direct_word certificate accepted (.policyHash limb)
  nextAccumulatorDigest limb :=
    accepted_current_direct_word certificate accepted (.nextAccumulatorDigest limb)
  valueLockDigest limb :=
    accepted_current_direct_word certificate accepted (.valueLockDigest limb)
  boundCurrent limb :=
    accepted_current_direct_word certificate accepted (.boundCurrent limb)
  boundSecondary limb :=
    accepted_current_direct_word certificate accepted (.boundSecondary limb)

private theorem packed_lane_row (packed : List Nat) {row lane : Nat}
    (rowBound : row < 686) (_laneBound : lane < 64) :
    (packedWitnessLaneRows packed lane).getD row 0 =
      packed.getD (row * 64 + lane) 0 := by
  simp [packedWitnessLaneRows, relationRowCount, packingFactor,
    List.getD_eq_getElem?_getD, rowBound]

/-- Package the selected seven-limb nonlinear comparison in the registry's
`FullTagMatch` type.  No five-limb legacy projection appears in this bridge. -/
def currentFullTagMatch {Key : Type*} {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (approvalSelected : (rows.getD approvalRow 0 : Goldilocks) = 1)
    (slot : SignerSlot)
    (membershipSelected : (rows.getD (membershipRow slot) 0 : Goldilocks) = 1)
    (signerKey : Key) : FullTagMatch Key Goldilocks :=
  fullTagMatchOfCoordinates slot signerKey
    (fun limb => (rows.getD (legacyTagRow limb) 0 : Goldilocks))
    (fun limb => (rows.getD (policyTagRow slot limb) 0 : Goldilocks))
    (fun limb => congrFun (local_selected_full_tag_equality semantic
      approvalSelected slot membershipSelected) limb)

/-- In Approval/Final mode the seven inline raw policy limbs are exactly the
digest emitted by policy sponge call 99.  The selector hypothesis is the
current row-282 `approval + final` value, not a host-side mode assertion. -/
theorem accepted_non_single_policy_digest
    {components : RelationProgramComponents}
    (localCertificate : CurrentLocalArtifactCertificate components)
    (directCertificate : CurrentDirectCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (nonSingleSelected : ∀ limb : Fin 7,
      (packedWitnessLaneRows packed limb.val).getD 282 0 = 1)
    (limb : Fin 7) :
    packed.getD (rawIndex (122 + limb.val)) 0 =
      packed.getD (hashFinalIndex 99 limb.val) 0 := by
  have semantic := packed_program_implies_local_semantics localCertificate accepted
    ⟨limb.val, by omega⟩
  have bridge := semantic (.policyDigestBridge limb)
  have selected :
      ((packedWitnessLaneRows packed limb.val).getD 282 0 : Goldilocks) = 1 := by
    simpa only [Nat.cast_one] using
      congrArg (fun value : Nat => (value : Goldilocks)) (nonSingleSelected limb)
  simp only [localCheckTerm, SourceTerm.eval, selected] at bridge
  rw [packed_lane_row packed (by decide) (by omega),
    packed_lane_row packed (by decide) (by omega)] at bridge
  have inlineEquality : packed.getD (280 * 64 + limb.val) 0 =
      packed.getD (281 * 64 + limb.val) 0 := by
    apply canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 (280 * 64 + limb.val))
      (packed_word_canonical accepted.2.1 (281 * 64 + limb.val))
    have fieldDifference :
        (packed.getD (280 * 64 + limb.val) 0 : Goldilocks) -
          (packed.getD (281 * 64 + limb.val) 0 : Goldilocks) = 0 := by
      linear_combination bridge
    have fieldEquality :
        (packedWord packed (280 * 64 + limb.val) : Goldilocks) =
          (packedWord packed (281 * 64 + limb.val) : Goldilocks) := by
      simpa only [packedWord] using sub_eq_zero.mp fieldDifference
    exact fieldEquality
  have rawCopy := accepted_current_direct_word directCertificate accepted
    (.policyRaw limb)
  have hashCopy := accepted_current_direct_word directCertificate accepted
    (.policyHash limb)
  exact rawCopy.symm.trans (inlineEquality.trans hashCopy)

/-- Final mode ties the accumulator's stored intent digest to the exact
104-word public intent sponge output at call 93. -/
theorem accepted_final_intent_digest
    {components : RelationProgramComponents}
    (localCertificate : CurrentLocalArtifactCertificate components)
    (directCertificate : CurrentDirectCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (finalSelected :
      (packedWitnessLaneRows packed 0).getD finalRow 0 = 1)
    (limb : Fin 7) :
    packed.getD (rawIndex (129 + limb.val)) 0 =
      packed.getD (hashFinalIndex 93 limb.val) 0 := by
  have semantic := packed_program_implies_local_semantics localCertificate accepted
    (0 : Fin 64)
  have selected :
      ((packedWitnessLaneRows packed 0).getD finalRow 0 : Goldilocks) = 1 := by
    simpa only [Nat.cast_one] using
      congrArg (fun value : Nat => (value : Goldilocks)) finalSelected
  have equation := semantic (.finalIntent limb)
  simp only [localCheckTerm, SourceTerm.eval] at equation
  rw [packed_lane_row packed (row := finalRow) (lane := (0 : Fin 64).val)
      (by decide) (by decide),
    packed_lane_row packed (row := 129 + limb.val) (lane := (0 : Fin 64).val)
      (by omega) (by decide),
    packed_lane_row packed (row := 115 + limb.val) (lane := (0 : Fin 64).val)
      (by omega) (by decide)] at equation
  have selectedPacked :
      (packed.getD (finalRow * 64 + (0 : Fin 64).val) 0 : Goldilocks) = 1 := by
    rw [← packed_lane_row packed (row := finalRow) (lane := (0 : Fin 64).val)
      (by decide) (by decide)]
    exact selected
  rw [selectedPacked] at equation
  have intentToStatement : packed.getD (rawIndex (129 + limb.val)) 0 =
      packed.getD (rawIndex (115 + limb.val)) 0 := by
    apply canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 (rawIndex (129 + limb.val)))
      (packed_word_canonical accepted.2.1 (rawIndex (115 + limb.val)))
    have fieldDifference :
        (packed.getD ((129 + limb.val) * 64) 0 : Goldilocks) -
          (packed.getD ((115 + limb.val) * 64) 0 : Goldilocks) = 0 := by
      linear_combination equation
    have fieldEquality :
        (packedWord packed ((129 + limb.val) * 64) : Goldilocks) =
          (packedWord packed ((115 + limb.val) * 64) : Goldilocks) := by
      simpa only [packedWord] using sub_eq_zero.mp fieldDifference
    simpa only [rawIndex,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.rawRowStart,
      Hegemon.Transaction.Poseidon2V8DecoderRefinement.packingFactor,
      Nat.zero_add] using fieldEquality
  have statementCopy := accepted_current_direct_word directCertificate accepted
    (.intentDigest limb)
  exact intentToStatement.trans statementCopy

/-- The typed Approval predecessor identity is the current accumulator bound
digest, not a free `inputNoteIdentity` coordinate. -/
theorem accepted_approval_predecessor_identity
    {components : RelationProgramComponents}
    (localCertificate : CurrentLocalArtifactCertificate components)
    (directCertificate : CurrentDirectCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (approvalSelected : ∀ limb : Fin 7,
      (packedWitnessLaneRows packed limb.val).getD approvalRow 0 = 1)
    (singleUnselected : ∀ limb : Fin 7,
      (packedWitnessLaneRows packed limb.val).getD singleRow 0 = 0)
    (finalUnselected : ∀ limb : Fin 7,
      (packedWitnessLaneRows packed limb.val).getD finalRow 0 = 0)
    (inputActive : (publicWords.getD 0 0 : Goldilocks) = 1)
    (limb : Fin 7) :
    packed.getD (inputNoteVectorRow 0 * 64 + limb.val) 0 =
      packed.getD (hashFinalIndex 107 limb.val) 0 := by
  have semantic := packed_program_implies_local_semantics localCertificate accepted
    ⟨limb.val, by omega⟩
  have approvalField :
      ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) = 1 := by
    simpa only [Nat.cast_one] using
      congrArg (fun value : Nat => (value : Goldilocks)) (approvalSelected limb)
  have singleField :
      ((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) = 0 := by
    simpa only [Nat.cast_zero] using
      congrArg (fun value : Nat => (value : Goldilocks)) (singleUnselected limb)
  have finalField :
      ((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks) = 0 := by
    simpa only [Nat.cast_zero] using
      congrArg (fun value : Nat => (value : Goldilocks)) (finalUnselected limb)
  have localProof := local_approval_input_zero_authorization semantic
    approvalField singleField finalField inputActive
  rw [packed_lane_row packed (by decide) (by omega),
    packed_lane_row packed (by decide) (by omega)] at localProof
  have copied := accepted_current_direct_word directCertificate accepted
    (.boundCurrent limb)
  have copiedFields := copied
  simp only [CurrentDirectWord.sourceIndex, CurrentDirectWord.targetIndex] at copiedFields
  have copiedRows :
      (packed.getD (boundCurrentVectorRow * 64 + limb.val) 0 : Goldilocks) =
        (packed.getD (hashFinalIndex 107 limb.val) 0 : Goldilocks) := by
    change (packed.getD (110 * 64 + limb.val) 0 : Goldilocks) = _
    exact congrArg (fun value : Nat => (value : Goldilocks)) copiedFields
  have fieldEquality :
      (packed.getD (inputNoteVectorRow 0 * 64 + limb.val) 0 : Goldilocks) =
        (packed.getD (hashFinalIndex 107 limb.val) 0 : Goldilocks) := by
    rw [localProof]
    exact copiedRows
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1
      (inputNoteVectorRow 0 * 64 + limb.val))
    (packed_word_canonical accepted.2.1 (hashFinalIndex 107 limb.val))
    fieldEquality

/-- Final input1 carries the same current accumulator identity. -/
theorem accepted_final_accumulator_identity
    {components : RelationProgramComponents}
    (localCertificate : CurrentLocalArtifactCertificate components)
    (directCertificate : CurrentDirectCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (finalSelected : ∀ limb : Fin 7,
      (packedWitnessLaneRows packed limb.val).getD finalRow 0 = 1)
    (singleUnselected : ∀ limb : Fin 7,
      (packedWitnessLaneRows packed limb.val).getD singleRow 0 = 0)
    (approvalUnselected : ∀ limb : Fin 7,
      (packedWitnessLaneRows packed limb.val).getD approvalRow 0 = 0)
    (inputActive : (publicWords.getD 1 0 : Goldilocks) = 1)
    (limb : Fin 7) :
    packed.getD (inputNoteVectorRow 1 * 64 + limb.val) 0 =
      packed.getD (hashFinalIndex 107 limb.val) 0 := by
  have semantic := packed_program_implies_local_semantics localCertificate accepted
    ⟨limb.val, by omega⟩
  have finalField :
      ((packedWitnessLaneRows packed limb.val).getD finalRow 0 : Goldilocks) = 1 := by
    simpa only [Nat.cast_one] using
      congrArg (fun value : Nat => (value : Goldilocks)) (finalSelected limb)
  have singleField :
      ((packedWitnessLaneRows packed limb.val).getD singleRow 0 : Goldilocks) = 0 := by
    simpa only [Nat.cast_zero] using
      congrArg (fun value : Nat => (value : Goldilocks)) (singleUnselected limb)
  have approvalField :
      ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) = 0 := by
    simpa only [Nat.cast_zero] using
      congrArg (fun value : Nat => (value : Goldilocks)) (approvalUnselected limb)
  have localProof := local_final_input_one_authorization semantic
    finalField singleField approvalField inputActive
  rw [packed_lane_row packed (by decide) (by omega),
    packed_lane_row packed (by decide) (by omega)] at localProof
  have copied := accepted_current_direct_word directCertificate accepted
    (.boundCurrent limb)
  have copiedFields := copied
  simp only [CurrentDirectWord.sourceIndex, CurrentDirectWord.targetIndex] at copiedFields
  have copiedRows :
      (packed.getD (boundCurrentVectorRow * 64 + limb.val) 0 : Goldilocks) =
        (packed.getD (hashFinalIndex 107 limb.val) 0 : Goldilocks) := by
    change (packed.getD (110 * 64 + limb.val) 0 : Goldilocks) = _
    exact congrArg (fun value : Nat => (value : Goldilocks)) copiedFields
  have fieldEquality :
      (packed.getD (inputNoteVectorRow 1 * 64 + limb.val) 0 : Goldilocks) =
        (packed.getD (hashFinalIndex 107 limb.val) 0 : Goldilocks) := by
    rw [localProof]
    exact copiedRows
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1
      (inputNoteVectorRow 1 * 64 + limb.val))
    (packed_word_canonical accepted.2.1 (hashFinalIndex 107 limb.val))
    fieldEquality

/-- Approval output0 carries the newly computed accumulator binding from call
108; this is the successful producer identity consumed by origin recovery. -/
theorem accepted_approval_output_accumulator_identity
    {components : RelationProgramComponents}
    (localCertificate : CurrentLocalArtifactCertificate components)
    (directCertificate : CurrentDirectCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed)
    (approvalSelected : ∀ limb : Fin 7,
      (packedWitnessLaneRows packed limb.val).getD approvalRow 0 = 1)
    (limb : Fin 7) :
    packed.getD (outputZeroVectorRow * 64 + limb.val) 0 =
      packed.getD (hashFinalIndex 108 limb.val) 0 := by
  have semantic := packed_program_implies_local_semantics localCertificate accepted
    ⟨limb.val, by omega⟩
  have approvalField :
      ((packedWitnessLaneRows packed limb.val).getD approvalRow 0 : Goldilocks) = 1 := by
    simpa only [Nat.cast_one] using
      congrArg (fun value : Nat => (value : Goldilocks)) (approvalSelected limb)
  have localProof := local_approval_output_full_authorization semantic
    approvalField
  rw [packed_lane_row packed (by decide) (by omega),
    packed_lane_row packed (by decide) (by omega)] at localProof
  have copied := accepted_current_direct_word directCertificate accepted
    (.boundSecondary limb)
  have copiedFields := copied
  simp only [CurrentDirectWord.sourceIndex, CurrentDirectWord.targetIndex] at copiedFields
  have copiedRows :
      (packed.getD (boundSecondaryVectorRow * 64 + limb.val) 0 : Goldilocks) =
        (packed.getD (hashFinalIndex 108 limb.val) 0 : Goldilocks) := by
    change (packed.getD (111 * 64 + limb.val) 0 : Goldilocks) = _
    exact congrArg (fun value : Nat => (value : Goldilocks)) copiedFields
  have fieldEquality :
      (packed.getD (outputZeroVectorRow * 64 + limb.val) 0 : Goldilocks) =
        (packed.getD (hashFinalIndex 108 limb.val) 0 : Goldilocks) := by
    rw [localProof]
    exact copiedRows
  exact canonical_nat_cast_injective
    (packed_word_canonical accepted.2.1
      (outputZeroVectorRow * 64 + limb.val))
    (packed_word_canonical accepted.2.1 (hashFinalIndex 108 limb.val))
    fieldEquality

/-- Fixed current certificate bundle.  Only finite attempt/root instances are
awaiting exporter regeneration; all meanings and coordinates are fixed here. -/
structure CurrentRp05AuthCertificate (components : RelationProgramComponents) where
  localSemantics : CurrentLocalArtifactCertificate components
  absorbed : CurrentAbsorbCertificate components
  frame : CurrentFrameCertificate components
  direct : CurrentDirectCertificate components

structure CurrentRp05AuthProjection
    (publicWords packed : List Nat) : Prop where
  semantics : ∀ lane : Fin 64,
    LocalSemanticRelation publicWords (packedWitnessLaneRows packed lane.val)
  encoders : CurrentEncoderProjection publicWords packed
  frame : CurrentFrameProjection packed
  digests : CurrentDigestProjection packed

theorem packed_program_implies_current_rp05_auth
    {components : RelationProgramComponents}
    (certificate : CurrentRp05AuthCertificate components)
    {publicWords packed : List Nat}
    (accepted : components.AcceptsPacked publicWords packed) :
    CurrentRp05AuthProjection publicWords packed where
  semantics lane :=
    packed_program_implies_local_semantics certificate.localSemantics accepted lane
  encoders := packed_program_implies_current_encoder_projection
    certificate.absorbed accepted
  frame := packed_program_implies_current_frame_projection certificate.frame accepted
  digests := packed_program_implies_current_digest_projection certificate.direct accepted

end HegemonCrypto.SmallWood.SmzaRp05AuthSourceBridge
