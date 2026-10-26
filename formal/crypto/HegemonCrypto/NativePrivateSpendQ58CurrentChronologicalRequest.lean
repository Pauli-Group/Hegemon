import HegemonCrypto.NativePrivateSpendQ58CurrentSelectedLeaf
import HegemonCrypto.NativePrivateSpendQ58CurrentResponseIndexedTransport
import HegemonCrypto.SmallWoodV8Smz9SourceIndexSampler
import HegemonCrypto.SmallWoodV8Smz9HonestLeafBatch

/-! ONE current chronological raw-request adapter. Prefix/DECS/PIOP roles share
one raw byte address carrier. Current PIOP batching reads6722970 field words;
DECS selection reads80 candidates under the distinct SMZD/COMPFF01 domain.
No legacy50-draw sampler,53-byte profile or legacy PCS opening policy is reused.
Each nonleaf fold leaves the incoming quantum registers and mutable oracle in
place. The selected-write factorization preserves both real error branches. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentChronologicalRequest
open Polynomial
open HegemonCrypto.CanonicalBytes
open Hegemon.Transaction.SmallWoodProductionConstraintRefinement
open V8Smz9ZeroKnowledge V8Smz9EagerPrivacy V8Smz9PiopOpeningRecovery
open V8Smz9HonestRequestSchedule V8Smz9HonestOpeningSchedule
open V8Smz9RuntimeDistribution V8Smz9HiddenLeafQrom V8Smz9HiddenPatch V8Smz9CurrentPrivacyGame
open V8Smz9RawCounterCompiler V8Smz9MixedMaskCompiler
open NativePrivateSpendQ58CurrentLeafInput NativePrivateSpendQ58CurrentSelectedLeaf
open scoped Classical BigOperators
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option stderrAsMessages false

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: D"
abbrev D := NativePrivateSpendQ58CurrentRowBoundary.D
#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: Q"
abbrev Q := NativePrivateSpendQ58CurrentRowBoundary.Q
#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: CurrentGamma"
abbrev CurrentGamma := Fin 5 → NativePrivateSpendQ58CurrentPublicOpening.Gamma
#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: FieldWord"
abbrev FieldWord := V8Smz9WholeViewObservation.FieldWord

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentPrefix"
/-- Exactly the source70-byte profile framing, with raw u64 values retained.
The trusted source interpretation supplies canonical fields and raw digest limbs. -/
def currentPrefix (role : List HegemonCrypto.CanonicalBytes.Byte) (words : List Nat) : List HegemonCrypto.CanonicalBytes.Byte :=
  encodeLE 8 70 ++ currentProfile ++ encodeLE 8 role.length ++ role ++
    encodeLE 8 words.length ++ (words.map (encodeLE 8)).flatten

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: current_counter_length"
theorem current_counter_length (role : List HegemonCrypto.CanonicalBytes.Byte) (words : List Nat)
    (counter : Fin (2 ^ 64)) :
    (counterInput (currentPrefix role words) counter).length = 102 + role.length + 8 * words.length := by
  have payload : ((words.map (encodeLE 8)).flatten).length = 8 * words.length := by
    induction words with
    | nil => rfl
    | cons word words ih => simp [encodeLE_length, ih, Nat.mul_add, Nat.add_comm]
  have profile : currentProfile.length = 70 := by decide
  simp only [counterInput, currentPrefix, List.length_append, encodeLE_length, profile, payload]
  omega

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentCounterKey"
def currentCounterKey (bound : Nat) (role : List HegemonCrypto.CanonicalBytes.Byte) (words : List Nat)
    (bounded : 102 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 102 + role.length + 8 * words.length ≠ leafBytes)
    (counter : Fin (2 ^ 64)) : CurrentOtherRawInput bound :=
  let input := counterInput (currentPrefix role words) counter
  ⟨⟨⟨input.length, Nat.lt_succ_of_le (by rw [current_counter_length]; exact bounded)⟩,
      input.get⟩, by
        change input.length ≠ leafBytes
        rw [current_counter_length]
        exact notLeaf⟩

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: current_counter_key_literal"
theorem current_counter_key_literal (bound : Nat) (role : List HegemonCrypto.CanonicalBytes.Byte) (words : List Nat)
    (bounded : 102 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 102 + role.length + 8 * words.length ≠ leafBytes)
    (counter : Fin (2 ^ 64)) :
    rawBytes (.inr (currentCounterKey bound role words bounded notLeaf counter)) =
      counterInput (currentPrefix role words) counter := List.ofFn_get _

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentFieldXof"
def currentFieldXof (bound : Nat) (role : List HegemonCrypto.CanonicalBytes.Byte) (words : List Nat)
    (bounded : 102 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 102 + role.length + 8 * words.length ≠ leafBytes)
    (requested : Nat) (countBound : requested ≤ 2 ^ 24) :
    NonleafProgram (CurrentOtherRawInput bound) (Option (List FieldWord)) :=
  sourceFieldReadLoop requested [] (List.ofFn fun index : Fin (digestCallCap requested) =>
    currentCounterKey bound role words bounded notLeaf ⟨index.val, by
      have cap : digestCallCap requested ≤ 2 ^ 21 + 4 := by
        unfold digestCallCap; split <;> omega
      exact lt_of_lt_of_le index.isLt (le_trans cap (by norm_num))⟩)

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: current_field_xof_query_bound"
theorem current_field_xof_query_bound (bound : Nat) (role : List HegemonCrypto.CanonicalBytes.Byte) (words : List Nat)
    (bounded : 102 + role.length + 8 * words.length ≤ bound)
    (notLeaf : 102 + role.length + 8 * words.length ≠ leafBytes)
    (requested : Nat) (countBound : requested ≤ 2 ^ 24) :
    NonleafProgram.readCount (currentFieldXof bound role words bounded notLeaf requested countBound) ≤
      digestCallCap requested :=
  (source_field_read_loop_count requested [] _).trans (by simp)

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: decsWords"
def decsWords (reply : D) : List Nat :=
  (List.ofFn fun repetition : Fin 5 => List.ofFn fun coefficient : Fin 13173 =>
    (reply repetition coefficient).val).flatten

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: current_decs_word_count"
theorem current_decs_word_count (reply : D) : (decsWords reply).length = 65865 := by
  norm_num only [decsWords, List.length_flatten, List.map_ofFn, Function.comp_def,
    List.length_ofFn, List.sum_ofFn, Finset.sum_const, Finset.card_univ,
    Fintype.card_fin, nsmul_eq_mul]

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: PiopPrefix"
structure PiopPrefix where
  hashFpp : DigestRegister
  sampledGamma : Option (List FieldWord)
  pendingFailure : Bool

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: piopPrefix"
def piopPrefix (bound : Nat) (largeEnough : 527737 ≤ bound)
    (hashMt : DigestRegister) (binding : Fin 77 → Goldilocks) (reply : D) (pending : Bool) :
    NonleafProgram (CurrentOtherRawInput bound) PiopPrefix :=
  let inputWords := sourceDigestWords hashMt ++ decsWords reply ++ List.ofFn (fun index => (binding index).val)
  .read (currentCounterKey bound SmallWoodTranscript.piopInputDomain inputWords
    (by simp only [inputWords, List.length_append, source_digest_word_count,
          current_decs_word_count, List.length_ofFn]
        have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
        rw [role]; omega)
    (by simp only [inputWords, List.length_append, source_digest_word_count,
          current_decs_word_count, List.length_ofFn]
        have role : SmallWoodTranscript.piopInputDomain.length = 35 := by decide
        rw [role]; decide) ⟨0, by norm_num⟩) fun hashFpp =>
      NonleafProgram.bind
        (currentFieldXof bound SmallWoodTranscript.piopCoefficientDomain (sourceDigestWords hashFpp)
          (by rw [source_digest_word_count]
              have role : SmallWoodTranscript.piopCoefficientDomain.length = 41 := by decide
              rw [role]; omega)
          (by rw [source_digest_word_count]
              have role : SmallWoodTranscript.piopCoefficientDomain.length = 41 := by decide
              rw [role]; decide) 6722970 (by norm_num))
        (fun sampled => .done ⟨hashFpp, sampled, sourcePendingFailure pending sampled⟩)

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: prefixGamma"
def prefixGamma («prefix» : PiopPrefix) : CurrentGamma := fun repetition check =>
  ((sourceReturnedWords 6722970 «prefix».sampledGamma).getD
    (repetition.val * 1344594 + check.val) 0).val

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: sourceData"
/-- Source coins construct actual PCS columns. P is coefficient-major; source
pcs_commit stores its ten polynomial blocks column-major. No fresh PCS is used. -/
def sourceData (values : NativePrivateSpendQ58CurrentRowBoundary.Values 26210)
    (witness : NativePrivateSpendQ58CurrentRowBoundary.W 26210)
    (pcs : NativePrivateSpendQ58CurrentRowBoundary.P) (masks : Q) :
    NativePrivateSpendQ58Compff01SourceColumns.SourceData where
  values := values
  witnessCoins := witness
  nonlinear := masks.1
  linearCoins := masks.2
  pcs := fun column coefficient => pcs coefficient column

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: sourceWitness"
def sourceWitness (values : NativePrivateSpendQ58CurrentRowBoundary.Values 26210)
    (coins : NativePrivateSpendQ58CurrentRowBoundary.W 26210) :
    NativePrivateSpendQ58CurrentPublicOpening.Witness := fun row =>
  NativePrivateSpendQ58Compff01SourceColumns.restoreWitness (values row) (coins row)

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentSourceModel"
/-- Concrete current constructor: batching gamma is decoded from THIS raw
PIOP prefix schedule at THIS persistent oracle/public binding and DECS reply.
There is no arbitrary Model or secret-dependent simulator coverage field. -/
def currentSourceModel (bound : Nat) (largeEnough : 527737 ≤ bound)
    (oracle : CurrentFullRawInput bound → DigestRegister)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (values : NativePrivateSpendQ58CurrentRowBoundary.Values 26210)
    (hashMt : DigestRegister) (binding : Fin 77 → Goldilocks)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma) (pending : Bool) :
    NativePrivateSpendQ58CurrentRowBoundary.CurrentModel where
  gamma := decsGamma
  heads := fun witness pcs masks =>
    NativePrivateSpendQ58Compff01OpeningContinuation.stackedHeads
      (NativePrivateSpendQ58Compff01SourceColumns.sourceCurrentColumns (sourceData values witness pcs masks))
  piopUnmasked := fun witness reply =>
    let gamma := prefixGamma (NonleafProgram.interpret (fun input => oracle (.inr input))
      (piopPrefix bound largeEnough hashMt binding reply pending))
    (fun repetition coefficient =>
      (sourceNonlinearQuotient NativePrivateSpendQ58CurrentPublicOpening.packing
        (NativePrivateSpendQ58CurrentPublicOpening.batchedNonlinear relation (gamma repetition)
          (sourceWitness values witness))).coeff coefficient.val,
     fun repetition coefficient =>
      (sourceLinearUnmasked (NativePrivateSpendQ58CurrentPublicOpening.weights relation (gamma repetition))
        (sourcePackingLagrange NativePrivateSpendQ58CurrentPublicOpening.packing)
        (sourceWitness values witness)).coeff (coefficient.val + 1))

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: compileNonleaf"
/-- Generic structural fold, instantiated only on current physical addresses.
This theorem preserves the same oracle/registers even for abort returns. -/
def compileNonleaf {bound : Nat} {Result Work : Type} [Fintype Work] :
    NonleafProgram (CurrentOtherRawInput bound) Result →
      (Result → MixedProgram (CurrentFullRawInput bound) Work) →
        MixedProgram (CurrentFullRawInput bound) Work
  | .done result, next => next result
  | .read input rest, next => .honestRead (.inr input) fun output => compileNonleaf (rest output) next

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: compile_nonleaf_executes"
theorem compile_nonleaf_executes {bound : Nat} {Result Work : Type} [Fintype Work]
    (randomized : Bool) (program : NonleafProgram (CurrentOtherRawInput bound) Result)
    (next : Result → MixedProgram (CurrentFullRawInput bound) Work)
    (oracle : CurrentFullRawInput bound → DigestRegister)
    (state : V8Smz9HonestWholeViewGames.GameState (Input := CurrentFullRawInput bound) (Work := Work)) :
    run randomized (compileNonleaf program next) oracle state =
      run randomized (next (NonleafProgram.interpret (fun input => oracle (.inr input)) program)) oracle state := by
  induction program with
  | done result => rfl
  | read input rest ih => exact ih _

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: selectedWrites"
/-- Persistent fixed writes of exactly the selected58 addresses. Their charged
raw reads are supplied by MixedMaskSemantics.compile, not free oracle advice. -/
def selectedWrites {bound : Nat} {Work : Type} [Fintype Work]
    (leaves : Fin 58 → CurrentLeafInput) (answers : Fin 58 → DigestRegister)
    (next : MixedProgram (CurrentFullRawInput bound) Work) : MixedProgram (CurrentFullRawInput bound) Work :=
  (List.ofFn (fun opening : Fin 58 => (leaves opening, answers opening))).foldr
    (fun entry rest => .write (.inl entry.1) entry.2 rest) next

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: selected_write_join"
/-- Exact current selected-leaf join after generic unopened-leaf erasure.
The continuation can contain the original Merkle paths, raw public strategy,
quantum gates and instruments. Neither the table nor registers are reset. -/
theorem selected_write_join {bound : Nat} {Work : Type} [Fintype Work]
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte) (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte) (points : Fin 6 → Goldilocks)
    (distinct : Function.Injective points)
    (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads)
    (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails)
    (gamma : NativePrivateSpendQ58CurrentPublicOpening.DecsGamma)
    (masks : NativePrivateSpendQ58CurrentPublicOpening.DecsResponse) (targets : Fin 58 → Goldilocks)
    (indices : Fin 58 → V8Smz9HiddenPatch.LeafIndex) (tapes : Fin 58 → LeafTape)
    (answers : Fin 58 → DigestRegister) (next : MixedProgram (CurrentFullRawInput bound) Work)
    (randomized : Bool) (oracle : CurrentFullRawInput bound → DigestRegister)
    (state : V8Smz9HonestWholeViewGames.GameState (Input := CurrentFullRawInput bound) (Work := Work)) :
    run randomized
      (selectedWrites (publicSelectedLeaves statement salt
        (NativePrivateSpendQ58CurrentPublicOpening.sourceDecsResponse heads tails gamma masks) gamma
        points distinct (NativePrivateSpendQ58Compff01OpeningContinuation.combinationHeads points heads)
        (NativePrivateSpendQ58Compff01OpeningContinuation.earlier points tails)
        (NativePrivateSpendQ58Compff01OpeningContinuation.fullSubset heads targets tails)
        targets indices tapes) answers next) oracle state =
    run randomized (selectedWrites (sourceSelectedLeaves statement salt heads tails masks targets indices tapes)
      answers next) oracle state := by
  rw [public_selected_leaf_addresses_are_source]

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: scopeReturn"
/-- Preserve the actual early-return precedence. DECS/nonce exhaustion is an
error before scope.finish; field-XOF poison rejects a completed value at finish.
Both retain their chronological raw prefix; neither is success conditioning. -/
def scopeReturn {Value : Type} (pending : Bool) : Except String Value → Except String Value :=
  V8Smz9SourceIndexSampler.sourceScopeReturn pending

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: early_error_preserved"
theorem early_error_preserved {Value : Type} (pending : Bool) (message : String) :
    scopeReturn (Value := Value) pending (.error message) = .error message := rfl

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: field_xof_poison_rejects_completed"
theorem field_xof_poison_rejects_completed {Value : Type} (value : Value) :
    scopeReturn true (.ok value) = .error "smallwood SHA-512 field-XOF rejection budget exhausted" := rfl


#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentOpeningAdmissible"
/-- Current SMZD has correction-factor validity, without historical
r^64/r^35/r^63 PCS entry restrictions of SMZ9/SMZA/SMZC. -/
def currentOpeningAdmissible (points : Fin 6 → Goldilocks) : Prop :=
  Function.Injective points ∧ (∀ opening, points opening ≠ 0) ∧
    (∀ opening (lane : Fin 64), points opening ≠ (lane.val : Goldilocks)) ∧
    linearPiopCorrectionFactor points ≠ 0

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentOpeningValid"
def currentOpeningValid (words : List FieldWord) : Bool :=
  decide (words.length = 6 ∧ currentOpeningAdmissible (sourcePointVector words))

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: OpeningChoice"
structure OpeningChoice where
  selected : Option (Fin 16 × List FieldWord)
  pendingFailure : Bool

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentOpeningXof"
def currentOpeningXof (bound : Nat) (largeEnough : 527737 ≤ bound)
    (nonce : Fin 16) (digest : DigestRegister) :
    NonleafProgram (CurrentOtherRawInput bound) (Option (List FieldWord)) :=
  currentFieldXof bound SmallWoodTranscript.piopOpeningDomain
    (nonce.val :: sourceDigestWords digest)
    (by rw [List.length_cons, source_digest_word_count]
        have role : SmallWoodTranscript.piopOpeningDomain.length = 37 := by decide
        rw [role]; omega)
    (by rw [List.length_cons, source_digest_word_count]
        have role : SmallWoodTranscript.piopOpeningDomain.length = 37 := by decide
        rw [role]; decide) 6 (by norm_num)

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentChooseOpeningLoop"
/-- Nonce0..15, then genuine early exhaustion. Source proving reads the chosen
XOF a second time on the same persistent raw table. -/
def currentChooseOpeningLoop (bound : Nat) (largeEnough : 527737 ≤ bound)
    (digest : DigestRegister) (pending : Bool) : List (Fin 16) →
      NonleafProgram (CurrentOtherRawInput bound) OpeningChoice
  | [] => .done ⟨none, pending⟩
  | nonce :: rest => NonleafProgram.bind (currentOpeningXof bound largeEnough nonce digest) fun sampled =>
      let words := sourceReturnedWords 6 sampled
      let failed := sourcePendingFailure pending sampled
      if currentOpeningValid words then
        NonleafProgram.bind (currentOpeningXof bound largeEnough nonce digest) fun repeated =>
          .done ⟨some (nonce, sourceReturnedWords 6 repeated), sourcePendingFailure failed repeated⟩
      else currentChooseOpeningLoop bound largeEnough digest failed rest

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentChooseOpening"
def currentChooseOpening (bound : Nat) (largeEnough : 527737 ≤ bound)
    (digest : DigestRegister) (pending : Bool) :
    NonleafProgram (CurrentOtherRawInput bound) OpeningChoice :=
  currentChooseOpeningLoop bound largeEnough digest pending (List.ofFn id)

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentFixedRole"
def currentFixedRole : List HegemonCrypto.CanonicalBytes.Byte :=
  [104,101,103,101,109,111,110,46,115,109,97,108,108,119,111,111,100,46,110,97,116,105,118,101,45,112,114,105,118,97,116,101,45,115,112,101,110,100,46,115,109,122,100,46,99,111,109,112,102,102,48,49,46,100,101,99,115,45,102,105,120,101,100,45,115,97,109,112,108,105,110,103,46,118,50]

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: collectCurrentIndices"
/-- Literal source scan: retain first58 distinct indices and stop; sort once.
The domain is2^23 and the only rejected residue is the top field word p-1. -/
def collectCurrentIndices : List FieldWord → List V8Smz9HiddenPatch.LeafIndex → List V8Smz9HiddenPatch.LeafIndex
  | [], selected => selected
  | candidate :: rest, selected =>
      if selected.length = 58 then selected else
      if candidate.val < (goldilocksModulus / 8388608) * 8388608 then
        let index : V8Smz9HiddenPatch.LeafIndex := ⟨candidate.val % 8388608, Nat.mod_lt _ (by decide)⟩
        if index ∈ selected then collectCurrentIndices rest selected
        else collectCurrentIndices rest (selected.concat index)
      else collectCurrentIndices rest selected

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: sortedCurrentIndices"
def sortedCurrentIndices (candidates : List FieldWord) : List V8Smz9HiddenPatch.LeafIndex :=
  (collectCurrentIndices candidates []).mergeSort (fun left right => decide (left.val ≤ right.val))

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: selectedCurrentIndices"
def selectedCurrentIndices (candidates : List FieldWord) : Option (Fin 58 → V8Smz9HiddenPatch.LeafIndex) :=
  let indices := sortedCurrentIndices candidates
  if enough : indices.length = 58 then some (fun index => indices.get (index.cast enough.symm)) else none

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: DecsSelection"
structure DecsSelection where
  challenge : DigestRegister
  sampledCandidates : Option (List FieldWord)
  indices : Option (Fin 58 → V8Smz9HiddenPatch.LeafIndex)
  pendingFailure : Bool

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: currentDecsSelection"
/-- One opening digest and one80-field-word fixed sampler, at most14 raw
counter calls. No DECS nonce/grind retry is present. -/
def currentDecsSelection (bound : Nat) (largeEnough : 1264811 ≤ bound)
    (digest : DigestRegister) (heads : Fin 12 → Fin 13115 → Goldilocks)
    (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Earlier) (pending : Bool) :
    NonleafProgram (CurrentOtherRawInput bound) DecsSelection :=
  let words := NativePrivateSpendQ58Compff01OpeningContinuation.openingChallengeWords
    (fun word => (sourceDigestPrefix digest word).val) heads tails
  .read (currentCounterKey bound SmallWoodTranscript.decsOpeningDomain words
    (by rw [NativePrivateSpendQ58Compff01OpeningContinuation.current_challenge_word_count]
        have role : SmallWoodTranscript.decsOpeningDomain.length = 37 := by decide
        rw [role]; omega)
    (by rw [NativePrivateSpendQ58Compff01OpeningContinuation.current_challenge_word_count]
        have role : SmallWoodTranscript.decsOpeningDomain.length = 37 := by decide
        rw [role]; decide) ⟨0, by norm_num⟩) fun challenge =>
      NonleafProgram.bind
        (currentFieldXof bound currentFixedRole (sourceDigestWords challenge)
          (by rw [source_digest_word_count]
              have role : currentFixedRole.length = 75 := by decide
              rw [role]; omega)
          (by rw [source_digest_word_count]
              have role : currentFixedRole.length = 75 := by decide
              rw [role]; decide) 80 (by norm_num))
        (fun sampled => .done ⟨challenge, sampled,
          selectedCurrentIndices (sourceReturnedWords 80 sampled), sourcePendingFailure pending sampled⟩)

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: current_selector_is_public"
/-- Source and public selectors are the SAME physical grammar after proven
reconstruction. Equality retains all field-read and fixed-pool failures. -/
theorem current_selector_is_public (bound : Nat) (largeEnough : 1264811 ≤ bound)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (gamma : Fin 5 → NativePrivateSpendQ58CurrentPublicOpening.Gamma)
    (data : NativePrivateSpendQ58Compff01SourceColumns.SourceData)
    (valid : NativePrivateSpendQ58CurrentPublicOpening.Satisfies relation data.values)
    (points : Fin 6 → Goldilocks)
    (outside : ∀ opening lane, points opening ≠ NativePrivateSpendQ58CurrentPublicOpening.packing lane)
    (digest : DigestRegister)
    (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Earlier) (pending : Bool) :
    currentDecsSelection bound largeEnough digest
      (NativePrivateSpendQ58CurrentPublicOpening.publicHeads relation
        (NativePrivateSpendQ58CurrentPublicOpening.sourceFields relation gamma data points) points) tails pending =
    currentDecsSelection bound largeEnough digest
      (NativePrivateSpendQ58Compff01OpeningContinuation.combinationHeads points
        (NativePrivateSpendQ58Compff01OpeningContinuation.stackedHeads
          (NativePrivateSpendQ58Compff01SourceColumns.sourceCurrentColumns data))) tails pending := by
  rw [NativePrivateSpendQ58CurrentPublicOpening.public_heads_are_current_matrix relation gamma data valid points outside]

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: linear_mask_nonconstant"
/-- The full source linear mask derives only its constant; coefficients1..132
are the original independent coins. No mask-opening equality is supplied. -/
theorem linear_mask_nonconstant (coins : Fin 132 → Goldilocks) (index : Fin 132) :
    (sourceLinearMask NativePrivateSpendQ58CurrentPublicOpening.packing coins).coeff
      (index.val + 1) = coins index := by
  exact V8Smz9EagerSimulator.source_linear_mask_nonconstant_coefficient
    NativePrivateSpendQ58CurrentPublicOpening.packing coins index

/-- Interpolation is field-linear across an abstract finite row family. -/
private theorem generic_weighted_lagrange_interpolation {F : Type*} [Field F]
    {Rows : Type*} [Fintype Rows] {Nodes : Type*} [DecidableEq Nodes]
    (nodes : Finset Nodes) (samples : Nodes → F)
    (weights : Rows → F) (rowValues : Rows → Nodes → F) :
    Lagrange.interpolate nodes samples
      (fun node => ∑ row, weights row * rowValues row node) =
      ∑ row, C (weights row) * Lagrange.interpolate nodes samples (rowValues row) := by
  have values : (fun node => ∑ row, weights row * rowValues row node) =
      ∑ row, weights row • rowValues row := by
    funext node
    simp only [Finset.sum_apply, Pi.smul_apply, smul_eq_mul]
  rw [values, map_sum]
  simp only [map_smul, smul_eq_C_mul]

/-- The genuine coefficient equation retains its named row-polynomial head.
Row identities are transported only over the abstract finite row family. -/
private theorem generic_coefficient_response_is_interpolated_offset
    {F : Type*} [Field F] {Rows : Type*} [Fintype Rows]
    {Nodes : Type*} [DecidableEq Nodes] {Index : Type*}
    (nodes : Finset Nodes) (samples : Nodes → F)
    (weights : Rows → F) (rowValues : Rows → Nodes → F)
    (rowPolynomials : Rows → F[X])
    (rowInterpolation : ∀ row, rowPolynomials row =
      Lagrange.interpolate nodes samples (rowValues row))
    (index : Index → Nat) (masks response : Index → F)
    (coefficientLaw : ∀ coefficient, response coefficient =
      (∑ row, C (weights row) * rowPolynomials row).coeff (index coefficient) +
        masks coefficient) :
    response = fun coefficient =>
      (Lagrange.interpolate nodes samples
        (fun node => ∑ row, weights row * rowValues row node)).coeff (index coefficient) +
        masks coefficient := by
  have rowSum : (∑ row, C (weights row) * rowPolynomials row) =
      ∑ row, C (weights row) * Lagrange.interpolate nodes samples (rowValues row) := by
    apply Finset.sum_congr rfl
    intro row _
    exact congrArg (fun polynomial : F[X] => C (weights row) * polynomial)
      (rowInterpolation row)
  have combined := Eq.trans rowSum
    (generic_weighted_lagrange_interpolation nodes samples weights rowValues).symm
  funext coefficient
  exact Eq.trans (coefficientLaw coefficient)
    (congrArg (fun polynomial : F[X] =>
      polynomial.coeff (index coefficient) + masks coefficient) combined)

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: decs_source_response_is_offset"
/-- Literal current DECS interpolation equals the row-boundary offset. The
field-linear interpolation law is proved once, independently of row count. -/
theorem decs_source_response_is_offset (gamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma)
    (heads : NativePrivateSpendQ58Compff01OpeningContinuation.Heads)
    (tails : NativePrivateSpendQ58Compff01OpeningContinuation.Tails) (masks : D) :
    NativePrivateSpendQ58CurrentPublicOpening.sourceDecsResponse heads tails gamma masks =
      NativePrivateSpendQ58CurrentRowBoundary.decsOffset gamma heads tails + masks := by
  fail_if_success
    run_tac (liftM (IO.eprintln "CHRONOLOGICAL_REQUEST_DECS_STEP: REPETITION_FUNEXT_START") : Lean.Elab.Tactic.TacticM Unit)
    fail
  funext repetition
  fail_if_success
    run_tac (liftM (IO.eprintln "CHRONOLOGICAL_REQUEST_DECS_STEP: ABSTRACT_COEFFICIENT_TRANSPORT_START") : Lean.Elab.Tactic.TacticM Unit)
    fail
  exact generic_coefficient_response_is_interpolated_offset
    (Finset.univ : Finset (Fin 13173))
    (fun node => (node.val : Goldilocks)) (gamma repetition)
    (fun row => Fin.append (tails row) (heads row))
    (NativePrivateSpendQ58Compff01SourceColumns.extendedRowPolynomial heads tails)
    (fun row => rfl)
    (fun coefficient : Fin 13173 => coefficient.val) (masks repetition)
    (NativePrivateSpendQ58CurrentPublicOpening.sourceDecsResponse heads tails gamma masks repetition)
    (fun coefficient => NativePrivateSpendQ58CurrentPublicOpening.source_decs_response_coefficient
      heads tails gamma masks repetition coefficient)

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: sourceResponse"
/-- Source response construction from shared ORIGINAL masks. The DECS reply
is formed first; THIS reply chooses the actual raw PIOP gamma prefix. -/
def sourceResponse (bound : Nat) (largeEnough : 527737 ≤ bound)
    (oracle : CurrentFullRawInput bound → DigestRegister)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (values : NativePrivateSpendQ58CurrentRowBoundary.Values 26210)
    (hashMt : DigestRegister) (binding : Fin 77 → Goldilocks)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma) (pending : Bool)
    (base : NativePrivateSpendQ58CurrentRowBoundary.Base 26210) (masks : Q × D) :
    NativePrivateSpendQ58CurrentRowBoundary.Response :=
  let data := sourceData values base.1 base.2.1 masks.1
  let heads := NativePrivateSpendQ58Compff01OpeningContinuation.stackedHeads
    (NativePrivateSpendQ58Compff01SourceColumns.sourceCurrentColumns data)
  let reply := NativePrivateSpendQ58CurrentPublicOpening.sourceDecsResponse heads base.2.2 decsGamma masks.2
  let gamma := prefixGamma (NonleafProgram.interpret (fun input => oracle (.inr input))
    (piopPrefix bound largeEnough hashMt binding reply pending))
  (reply,
    (fun repetition => NativePrivateSpendQ58CurrentPublicOpening.nonlinearResponse relation (gamma repetition)
      (sourceWitness values base.1) (masks.1.1 repetition),
     fun repetition => NativePrivateSpendQ58CurrentPublicOpening.linearResponse relation (gamma repetition)
      (sourceWitness values base.1) (masks.1.2 repetition)))

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: source_response_is_mask_forward"
theorem source_response_is_mask_forward (bound : Nat) (largeEnough : 527737 ≤ bound)
    (oracle : CurrentFullRawInput bound → DigestRegister)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (values : NativePrivateSpendQ58CurrentRowBoundary.Values 26210)
    (hashMt : DigestRegister) (binding : Fin 77 → Goldilocks)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma) (pending : Bool)
    (base : NativePrivateSpendQ58CurrentRowBoundary.Base 26210) (masks : Q × D) :
    sourceResponse bound largeEnough oracle relation values hashMt binding decsGamma pending base masks =
      NativePrivateSpendQ58CurrentRowBoundary.maskForward
        (currentSourceModel bound largeEnough oracle relation values hashMt binding decsGamma pending) base masks := by
  unfold sourceResponse
  dsimp only
  rw [decs_source_response_is_offset]
  apply Prod.ext
  · rfl
  · apply Prod.ext
    · funext repetition coefficient
      simp only [NativePrivateSpendQ58CurrentPublicOpening.nonlinearResponse,
        NativePrivateSpendQ58CurrentPublicOpening.nonlinearTranscript, sourceNonlinearTranscript,
        coeff_add, NativePrivateSpendQ58Compff01SourceColumns.coefficient_array_at,
        dif_pos coefficient.isLt, NativePrivateSpendQ58CurrentRowBoundary.maskForward,
        currentSourceModel, Pi.add_apply, Prod.fst_add]
    · funext repetition coefficient
      simp only [NativePrivateSpendQ58CurrentPublicOpening.linear_response_coefficient,
        NativePrivateSpendQ58CurrentRowBoundary.maskForward,
        currentSourceModel, Pi.add_apply, Prod.snd_add]

/-- Pointwise genuine source and inverse identities transport the kernel
average while its mask and response types remain abstract. -/
private theorem generic_inverse_kernel_average {Masks Response : Type*}
    [Fintype Masks] [Nonempty Masks]
    (source forward : Masks → Response) (inverse : Response → Masks)
    (sourceForward : ∀ masks, source masks = forward masks)
    (inverseForward : ∀ masks, inverse (forward masks) = masks)
    (kernel : Masks → Response → ℝ) :
    uniformAverage (fun masks => kernel masks (source masks)) =
      uniformAverage (fun masks => kernel (inverse (forward masks)) (forward masks)) := by
  apply congrArg uniformAverage
  funext masks
  rw [inverseForward, sourceForward]

/-- The entire inverse-aware response and product-average transport is
proved before specializing the finite source and product spaces. -/
private theorem generic_pre_transcript_transport
    {Masks Reply Transcript : Type}
    [Fintype Masks] [Nonempty Masks] [Fintype Reply] [Nonempty Reply]
    [Fintype Transcript] [Nonempty Transcript]
    (source forward : Masks → Reply × Transcript)
    (inverse : Reply × Transcript → Masks)
    (equivalence : Masks ≃ Reply × Transcript)
    (sourceForward : ∀ masks, source masks = forward masks)
    (inverseForward : ∀ masks, inverse (forward masks) = masks)
    (forwardEquiv : ∀ masks, forward masks = equivalence masks)
    (kernel : Masks → (Reply × Transcript) → ℝ) :
    uniformAverage (fun masks => kernel masks (source masks)) =
      uniformAverage (fun reply => uniformAverage (fun transcript =>
        kernel (inverse (reply, transcript)) (reply, transcript))) := by
  calc
    _ = uniformAverage (fun masks =>
        kernel (inverse (forward masks)) (forward masks)) :=
      generic_inverse_kernel_average source forward inverse sourceForward inverseForward kernel
    _ = uniformAverage (fun response : Reply × Transcript => kernel (inverse response) response) := by
      simpa only [forwardEquiv] using uniform_average_equiv equivalence
        (fun response => kernel (inverse response) response)
    _ = _ := V8Smz9HonestLeafBatch.uniform_average_product
      (fun reply transcript => kernel (inverse (reply, transcript)) (reply, transcript))

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: current_pre_transcript_transport"
/-- Exact actual source transport at the PRE-transcript phase, conditional only
on the preceding public prefix/DECS raw reply. The kernel retains inverse
original masks and may contain the same public strategy, persistent raw oracle
and incoming quantum registers, including both abort observations. The desired
joint uniformity is DERIVED by the concrete source constructor and bijection.
It is not an input premise. This does not condition on the later final proof. -/
theorem current_pre_transcript_transport (bound : Nat) (largeEnough : 527737 ≤ bound)
    (oracle : CurrentFullRawInput bound → DigestRegister)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (values : NativePrivateSpendQ58CurrentRowBoundary.Values 26210)
    (hashMt : DigestRegister) (binding : Fin 77 → Goldilocks)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma) (pending : Bool)
    (base : NativePrivateSpendQ58CurrentRowBoundary.Base 26210)
    (kernel : (Q × D) → NativePrivateSpendQ58CurrentRowBoundary.Response → ℝ) :
    uniformAverage (fun masks : Q × D => kernel masks
      (sourceResponse bound largeEnough oracle relation values hashMt binding decsGamma pending base masks)) =
    uniformAverage (fun reply : D => uniformAverage (fun transcript : Q =>
      kernel (NativePrivateSpendQ58CurrentRowBoundary.maskInverse
        (currentSourceModel bound largeEnough oracle relation values hashMt binding decsGamma pending)
        base (reply, transcript)) (reply, transcript))) := by
  let model := currentSourceModel bound largeEnough oracle relation values hashMt binding decsGamma pending
  exact generic_pre_transcript_transport
    (sourceResponse bound largeEnough oracle relation values hashMt binding decsGamma pending base)
    (NativePrivateSpendQ58CurrentRowBoundary.maskForward model base)
    (NativePrivateSpendQ58CurrentRowBoundary.maskInverse model base)
    (NativePrivateSpendQ58CurrentRowBoundary.maskEquiv model base)
    (fun masks => source_response_is_mask_forward bound largeEnough oracle relation values
      hashMt binding decsGamma pending base masks)
    (NativePrivateSpendQ58CurrentRowBoundary.mask_inverse_forward model base)
    (fun masks => rfl) kernel

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_DECL_START: current_source_joint_response_uniform"
/-- The concrete source response pushforward is uniform jointly. This is the
actual shared-mask law underlying the pre-transcript input sampler. -/
theorem current_source_joint_response_uniform (bound : Nat) (largeEnough : 527737 ≤ bound)
    (oracle : CurrentFullRawInput bound → DigestRegister)
    (relation : NativePrivateSpendQ58CurrentPublicOpening.Relation)
    (values : NativePrivateSpendQ58CurrentRowBoundary.Values 26210)
    (hashMt : DigestRegister) (binding : Fin 77 → Goldilocks)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma) (pending : Bool)
    (base : NativePrivateSpendQ58CurrentRowBoundary.Base 26210) :
    pmfMap (uniformFintypePMF (Q × D))
      (sourceResponse bound largeEnough oracle relation values hashMt binding decsGamma pending base) =
      uniformFintypePMF NativePrivateSpendQ58CurrentRowBoundary.Response := by
  have functions : sourceResponse bound largeEnough oracle relation values hashMt binding decsGamma pending base =
      NativePrivateSpendQ58CurrentRowBoundary.maskForward
        (currentSourceModel bound largeEnough oracle relation values hashMt binding decsGamma pending) base := by
    funext masks
    exact source_response_is_mask_forward bound largeEnough oracle relation values hashMt binding decsGamma pending base masks
  rw [functions]
  exact V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv (NativePrivateSpendQ58CurrentRowBoundary.maskEquiv
    (currentSourceModel bound largeEnough oracle relation values hashMt binding decsGamma pending) base)

#eval IO.eprintln "CHRONOLOGICAL_REQUEST_COMPILE_COMPLETE"

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentChronologicalRequest
