import HegemonCrypto.NativePrivateSpendQ58CurrentCosetSelector
import HegemonCrypto.NativePrivateSpendQ58CurrentCoinObservation
import HegemonCrypto.NativePrivateSpendQ58CurrentFreshInitialized

/-! ONE total public SMZD continuation from the preceding public commit/DECS
prefix. Its public data, all error branches, reads, fresh samplers and fixed
writes belong to one MixedProgram. The initialized theorem compares that SAME
program with the SAME original registers and persistent raw oracle.

This is a concrete initialized public-program/fresh-hop endpoint. It does not
assert the unproved full native-request-to-public-program erasure join. The
finite source observation/response bridges are imported, rather than supplied
as desired equality or uniformity assumptions. -/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentInitializedPublic
open V8Smz9ZeroKnowledge V8Smz9RuntimeDistribution V8Smz9HiddenLeafQrom
open V8Smz9HonestOpeningSchedule V8Smz9HonestRequestSchedule
open V8Smz9MixedMaskCompiler V8Smz9RawCounterCompiler
open NativePrivateSpendQ58CurrentLeafInput NativePrivateSpendQ58CurrentTranscriptInput
open NativePrivateSpendQ58CurrentSelectedLeaf NativePrivateSpendQ58CurrentChronologicalRequest
open NativePrivateSpendQ58CurrentCosetSelector NativePrivateSpendQ58CurrentCoinObservation
open HegemonCrypto.CmsCompressedOracle HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsQuerySequence
open Q38WholeViewCmsSemantics NativePrivateSpendQ58CurrentFreshAccounting
open NativePrivateSpendQ58CurrentFreshNumerics NativePrivateSpendQ58CurrentFreshInitialized
open scoped Classical ENNReal
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0
set_option stderrAsMessages false

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: CurrentPublicScalars"

abbrev CurrentPublicScalars :=
  NativePrivateSpendQ58CurrentRowBoundary.W 26210 × NativePrivateSpendQ58CurrentRowBoundary.P
#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: CurrentEarlier"

abbrev CurrentEarlier := NativePrivateSpendQ58Compff01OpeningContinuation.Earlier
#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: CurrentLater"

abbrev CurrentLater := NativePrivateSpendQ58Compff01OpeningContinuation.Later
#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: PublicRelation"

abbrev PublicRelation := NativePrivateSpendQ58CurrentPublicOpening.Relation

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: publicReplySource"

def publicReplySource : V8Smz9HonestWholeViewGames.RandomSource where
  Coins := D
  finite := inferInstance
  inhabited := inferInstance

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: publicScalarSource"

def publicScalarSource : V8Smz9HonestWholeViewGames.RandomSource where
  Coins := CurrentPublicScalars
  finite := inferInstance
  inhabited := inferInstance

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: publicEarlierSource"

def publicEarlierSource : V8Smz9HonestWholeViewGames.RandomSource where
  Coins := CurrentEarlier
  finite := inferInstance
  inhabited := inferInstance

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: publicLaterSource"

def publicLaterSource : V8Smz9HonestWholeViewGames.RandomSource where
  Coins := CurrentLater
  finite := inferInstance
  inhabited := inferInstance

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: PublicResult"

structure PublicResult where
  reply : D
  «prefix» : PiopPrefix
  transcript : Q
  digest : DigestRegister
  nonce : Fin 16
  points : Fin 6 → Goldilocks
  fields : NativePrivateSpendQ58CurrentPublicOpening.PublicFields
  earlier : CurrentEarlier
  later : CurrentLater
  indices : Fin 58 → Index
  tapes : Fin 58 → LeafTape

variable {Work : Type} [Fintype Work]

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: selectedFreshLoop"

/-- A raw tape is selected at its actual hidden-leaf programming phase. The
fixed public label is then written at that exact key. Both events share one
table; the compiler charges one raw read for each fixed write. -/
def selectedFreshLoop {bound : Nat}
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Fin 58 → Fin 1176 → HegemonCrypto.CanonicalBytes.Byte)
    (indices : Fin 58 → Index) (labels : Index → DigestRegister)
    (next : (Fin 58 → LeafTape) → MixedProgram (CurrentFullRawInput bound) Work) :
    List (Fin 58) → (Fin 58 → LeafTape) → MixedProgram (CurrentFullRawInput bound) Work
  | [], tapes => next tapes
  | opening :: rest, tapes =>
      currentLeaf bound statement salt (payload opening) (indices opening) fun tape _ =>
        .write (.inl (NativePrivateSpendQ58CurrentLeafInput.sourceLeafInput statement salt
          (payload opening) (indices opening) tape)) (labels (indices opening))
          (selectedFreshLoop statement salt payload indices labels next rest
            (Function.update tapes opening tape))

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: selected_fresh_loop_mass"

theorem selected_fresh_loop_mass {bound : Nat}
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (payload : Fin 58 → Fin 1176 → HegemonCrypto.CanonicalBytes.Byte)
    (indices : Fin 58 → Index) (labels : Index → DigestRegister)
    (next : (Fin 58 → LeafTape) → MixedProgram (CurrentFullRawInput bound) Work)
    (remaining : ∀ tapes, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next tapes))
    (openings : List (Fin 58)) (tapes : Fin 58 → LeafTape) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
      (selectedFreshLoop statement salt payload indices labels next openings tapes) := by
  induction openings generalizing tapes with
  | nil => exact remaining tapes
  | cons opening rest ih =>
      apply current_leaf_preserves_mass
      intro tape answer
      exact ih _

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: compile_nonleaf_mass"

/-- Nonleaf folds contain no selected fresh event. Their raw reads remain
charged, and every possible answer retains the continuation's mass bound. -/
theorem compile_nonleaf_mass {bound : Nat} {Result : Type}
    (program : V8Smz9HonestRequestSchedule.NonleafProgram (CurrentOtherRawInput bound) Result)
    (next : Result → MixedProgram (CurrentFullRawInput bound) Work)
    (remaining : ∀ result, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next result)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (compileNonleaf program next) := by
  induction program with
  | done result => exact remaining result
  | read input rest ih => exact ih

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: afterDecs"

def afterDecs {bound : Nat} (descriptor : Descriptor)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma)
    (labels : Index → DigestRegister)
    (reply : D) («prefix» : PiopPrefix) (transcript : Q) (digest : DigestRegister)
    (nonce : Fin 16) (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (fields : NativePrivateSpendQ58CurrentPublicOpening.PublicFields)
    (heads : PublicHeads) (earlier : CurrentEarlier) (selection : DecsSelection)
    (next : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work) :
    MixedProgram (CurrentFullRawInput bound) Work :=
  match selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates) with
  | none => next (.error "fixed DECS sampler exhausted its candidate pool")
  | some selected =>
      .random publicLaterSource fun later =>
        let targets := selectedTargets descriptor selected
        let rows := publicSelectedRows points distinct heads earlier targets.val later
        let masks := publicSelectedMasks reply decsGamma rows targets.val
        selectedFreshLoop statement salt (fun opening => leafPayload (rows opening) (masks opening))
          selected.val labels (fun tapes => next (scopeReturn selection.pendingFailure
            (.ok ⟨reply, «prefix», transcript, digest, nonce, points, fields, earlier, later,
              selected.val, tapes⟩))) (List.ofFn id) (fun _ => 0)

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: after_decs_mass"

theorem after_decs_mass {bound : Nat} (descriptor : Descriptor)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma)
    (labels : Index → DigestRegister)
    (reply : D) («prefix» : PiopPrefix) (transcript : Q) (digest : DigestRegister)
    (nonce : Fin 16) (points : Fin 6 → Goldilocks) (distinct : Function.Injective points)
    (fields : NativePrivateSpendQ58CurrentPublicOpening.PublicFields)
    (heads : PublicHeads) (earlier : CurrentEarlier) (selection : DecsSelection)
    (next : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work)
    (remaining : ∀ result, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next result)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
      (afterDecs descriptor statement salt decsGamma labels reply «prefix» transcript digest
        nonce points distinct fields heads earlier selection next) := by
  unfold afterDecs
  split
  · exact remaining _
  · intro later
    apply selected_fresh_loop_mass
    intro tapes
    exact remaining _

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: afterOpening"

/-- The guard supplies only the success proof to dependent public algebra.
For the actual chronological selector it is redundant, as certified by
`current_selected_opening_valid`; it introduces no reachable new error. -/
def afterOpening {bound : Nat} (largeEnough : 1264811 ≤ bound)
    (descriptor : Descriptor) (relation : PublicRelation)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma)
    (labels : Index → DigestRegister)
    (reply : D) («prefix» : PiopPrefix) (transcript : Q) (digest : DigestRegister)
    (choice : OpeningChoice)
    (next : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work) :
    MixedProgram (CurrentFullRawInput bound) Work :=
  match choice.selected with
  | none => next (.error "smallwood opening nonce trial limit exhausted")
  | some (nonce, words) =>
      if valid : currentOpeningAdmissible (sourcePointVector words) then
        .random publicScalarSource fun scalars =>
          let points := sourcePointVector words
          let fields := observedPublicFields (prefixGamma «prefix») transcript scalars
          let heads := NativePrivateSpendQ58CurrentPublicOpening.publicHeads relation fields points
          .random publicEarlierSource fun earlier =>
            compileNonleaf (currentDecsSelection bound largeEnough digest heads earlier choice.pendingFailure)
              (fun selection => afterDecs descriptor statement salt decsGamma labels reply «prefix»
                transcript digest nonce points valid.1 fields heads earlier selection next)
      else next (.error "smallwood opening nonce trial limit exhausted")

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: after_opening_mass"

theorem after_opening_mass {bound : Nat} (largeEnough : 1264811 ≤ bound)
    (descriptor : Descriptor) (relation : PublicRelation)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma)
    (labels : Index → DigestRegister)
    (reply : D) («prefix» : PiopPrefix) (transcript : Q) (digest : DigestRegister)
    (choice : OpeningChoice)
    (next : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work)
    (remaining : ∀ result, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next result)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
      (afterOpening largeEnough descriptor relation statement salt decsGamma labels
        reply «prefix» transcript digest choice next) := by
  rcases choice with ⟨selectedChoice, pendingFailure⟩
  cases selectedChoice with
  | none =>
      dsimp only [afterOpening]
      exact remaining (.error "smallwood opening nonce trial limit exhausted")
  | some selectedValue =>
      rcases selectedValue with ⟨nonce, words⟩
      dsimp only [afterOpening]
      split
      · rename_i valid
        intro scalars earlier
        change CurrentPublicScalars at scalars
        change CurrentEarlier at earlier
        dsimp only [currentOpeningAdmissible] at valid
        with_reducible
          exact compile_nonleaf_mass (Work := Work) (bound := bound) (Result := DecsSelection)
            (currentDecsSelection bound largeEnough digest
              (NativePrivateSpendQ58CurrentPublicOpening.publicHeads relation
                (observedPublicFields (prefixGamma «prefix») transcript scalars)
                (sourcePointVector words)) earlier pendingFailure)
            (fun selection => afterDecs descriptor statement salt decsGamma labels reply «prefix»
              transcript digest nonce (sourcePointVector words) valid.1
              (observedPublicFields (prefixGamma «prefix») transcript scalars)
              (NativePrivateSpendQ58CurrentPublicOpening.publicHeads relation
                (observedPublicFields (prefixGamma «prefix») transcript scalars)
                (sourcePointVector words)) earlier selection next)
            (fun selection => after_decs_mass (Work := Work) (bound := bound)
              descriptor statement salt decsGamma labels reply «prefix» transcript digest nonce
              (sourcePointVector words) valid.1
              (observedPublicFields (prefixGamma «prefix») transcript scalars)
              (NativePrivateSpendQ58CurrentPublicOpening.publicHeads relation
                (observedPublicFields (prefixGamma «prefix») transcript scalars)
                (sourcePointVector words)) earlier selection next remaining)
      · exact remaining (.error "smallwood opening nonce trial limit exhausted")

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: publicRequest"

/-- Concrete witness-free public continuation. Prefix values/labels are the
preceding PUBLIC commit/DECS state after unopened-leaf erasure. No witness,
source-mask, arbitrary Model, observation equality or coverage field occurs
in this constructor. Q is sampled at the pre-final-transcript phase, not
conditioned on its later disclosure. Error continuations are total. -/
def publicRequest {bound : Nat} (largeEnough : 1264811 ≤ bound)
    (relation : PublicRelation)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (hashMt : DigestRegister) (binding : Fin 77 → Goldilocks)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma) (pending : Bool)
    (labels : Index → DigestRegister)
    (next : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work) :
    MixedProgram (CurrentFullRawInput bound) Work :=
  match currentDescriptor with
  | none => next (.error "smallwood strict-ZK DECS coset search exhausted")
  | some descriptor =>
      .random publicReplySource fun reply =>
        compileNonleaf (piopPrefix bound (by omega) hashMt binding reply pending) fun «prefix» =>
          transcriptRequest bound (by omega) (sourceDigestPrefix «prefix».hashFpp) fun transcript digest =>
            compileNonleaf (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
              (fun choice => afterOpening largeEnough descriptor relation statement salt decsGamma
                labels reply «prefix» transcript digest choice next)

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: public_request_mass"

theorem public_request_mass {bound : Nat} (largeEnough : 1264811 ≤ bound)
    (relation : PublicRelation)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (hashMt : DigestRegister) (binding : Fin 77 → Goldilocks)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma) (pending : Bool)
    (labels : Index → DigestRegister)
    (next : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work)
    (remaining : ∀ result, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next result)) :
    InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
      (publicRequest largeEnough relation statement salt hashMt binding decsGamma pending labels next) := by
  have massForDescriptor (descriptorChoice : Option Descriptor) :
      InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
        (match descriptorChoice with
        | none => next (.error "smallwood strict-ZK DECS coset search exhausted")
        | some descriptor =>
            .random publicReplySource fun reply =>
              compileNonleaf (piopPrefix bound (by omega) hashMt binding reply pending)
                (fun «prefix» => transcriptRequest bound (by omega)
                  (sourceDigestPrefix «prefix».hashFpp)
                  (fun transcript digest => compileNonleaf
                    (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
                    (fun choice => afterOpening largeEnough descriptor relation statement salt
                      decsGamma labels reply «prefix» transcript digest choice next)))) := by
    cases descriptorChoice with
    | none => exact remaining _
    | some descriptor =>
        intro reply
        change D at reply
        let openingContinuation («prefix» : PiopPrefix) (transcript : Q)
            (digest : DigestRegister) (choice : OpeningChoice) :
            MixedProgram (CurrentFullRawInput bound) Work :=
          afterOpening largeEnough descriptor relation statement salt decsGamma labels
            reply «prefix» transcript digest choice next
        have openingMass («prefix» : PiopPrefix) (transcript : Q)
            (digest : DigestRegister) (choice : OpeningChoice) :
            InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
              (openingContinuation «prefix» transcript digest choice) :=
          after_opening_mass (Work := Work) (bound := bound)
            largeEnough descriptor relation statement salt decsGamma labels
            reply «prefix» transcript digest choice next remaining
        let chooseContinuation («prefix» : PiopPrefix) (transcript : Q)
            (digest : DigestRegister) : MixedProgram (CurrentFullRawInput bound) Work :=
          compileNonleaf (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
            (openingContinuation «prefix» transcript digest)
        have chooseMass («prefix» : PiopPrefix) (transcript : Q) (digest : DigestRegister) :
            InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
              (chooseContinuation «prefix» transcript digest) := by
          with_reducible
            exact compile_nonleaf_mass (Work := Work) (bound := bound) (Result := OpeningChoice)
              (currentChooseOpening bound (by omega) digest «prefix».pendingFailure)
              (openingContinuation «prefix» transcript digest)
              (openingMass «prefix» transcript digest)
        let transcriptContinuation («prefix» : PiopPrefix) :
            MixedProgram (CurrentFullRawInput bound) Work :=
          transcriptRequest bound (by omega) (sourceDigestPrefix «prefix».hashFpp)
            (chooseContinuation «prefix»)
        have transcriptMass («prefix» : PiopPrefix) :
            InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (transcriptContinuation «prefix») := by
          with_reducible
            exact transcript_request_preserves_mass (Work := Work)
              bound (by omega) (sourceDigestPrefix «prefix».hashFpp)
              (chooseContinuation «prefix») (chooseMass «prefix»)
        have prefixMass : InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹
            (compileNonleaf (piopPrefix bound (by omega) hashMt binding reply pending)
              transcriptContinuation) := by
          with_reducible
            exact compile_nonleaf_mass (Work := Work) (bound := bound) (Result := PiopPrefix)
              (piopPrefix bound (by omega) hashMt binding reply pending)
              transcriptContinuation transcriptMass
        with_reducible exact prefixMass
  unfold publicRequest
  with_reducible exact massForDescriptor currentDescriptor

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: selected_guard_redundant"

/-- Successful repeated-nonce reads on the same raw table satisfy the guard.
Its complement is unreachable even when a field-XOF failure is pending. -/
theorem selected_guard_redundant {bound : Nat} (largeEnough : 527737 ≤ bound)
    (digest : DigestRegister) (pending : Bool)
    (oracle : CurrentOtherRawInput bound → DigestRegister)
    (nonce : Fin 16) (words : List FieldWord)
    (selected : (V8Smz9HonestRequestSchedule.NonleafProgram.interpret oracle
      (currentChooseOpening bound largeEnough digest pending)).selected = some (nonce, words)) :
    currentOpeningAdmissible (sourcePointVector words) :=
  (current_selected_opening_valid bound largeEnough digest pending oracle nonce words selected).2

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: public_indices_are_actual"

/-- The actual fixed-pool selector and its exhaustion return are retained.
The proof-bearing vector changes only its type, not the58 published indices. -/
theorem public_indices_are_actual (selection : DecsSelection)
    (constructed : selection.indices = selectedCurrentIndices
      (sourceReturnedWords 80 selection.sampledCandidates)) :
    (selectedCertificate (sourceReturnedWords 80 selection.sampledCandidates)).map Subtype.val =
      selection.indices := by
  rw [certificate_has_actual_indices, constructed]

variable [DecidableEq Work]

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: initialized_public_request_fresh_bound"

/-- One empty-CMS initialization for the concrete complete public continuation.
The continuation mass premise governs only later caller-supplied fresh input
events. It is not a source/public simulation or view-uniformity assertion.
`queries` bounds all raw queries in THIS program, including fixed writes and
the public adversary; it is not a production runtime limiter. -/
theorem initialized_public_request_fresh_bound {bound : Nat}
    (largeEnough : 1264811 ≤ bound) (relation : PublicRelation)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (hashMt : DigestRegister) (binding : Fin 77 → Goldilocks)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma) (pending : Bool)
    (labels : Index → DigestRegister)
    (next : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work)
    (remaining : ∀ result, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next result))
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := CurrentFullRawInput bound) (Work := Work))
    (queries : Nat)
    (registers : RegisterBasis (Input := CurrentFullRawInput bound) (Phase := DigestRegister)
      (Workspace := Work) → ℂ)
    (normalized : ‖(WithLp.toLp 2 registers :
      V8Smz9HonestWholeViewGames.GameState (Input := CurrentFullRawInput bound) (Work := Work))‖ = 1)
    (queryBound : queryCount
      (publicRequest largeEnough relation statement salt hashMt binding decsGamma pending labels next) ≤ queries) :
    |actualPhaseRun queries true
        (compile (publicRequest largeEnough relation statement salt hashMt binding decsGamma pending labels next) [])
        (partialRandomOracleState (Output := DigestRegister) ∅ (responseFourierRegisters registers)) -
      actualPhaseRun queries false
        (compile (publicRequest largeEnough relation statement salt hashMt binding decsGamma pending labels next) [])
        (partialRandomOracleState (Output := DigestRegister) ∅ (responseFourierRegisters registers))| ≤
      freshLifetimeLoss queries :=
  initialized_persistent_mixed_fresh_bound ghhm _ queries registers normalized queryBound
    (public_request_mass largeEnough relation statement salt hashMt binding decsGamma pending labels next remaining)

#eval IO.eprintln "INITIALIZED_PUBLIC_DECL_START: initialized_public_request_fresh_below_128"

/-- Exact initialized comparison rounded after its total query bound, using
the retained128-bit ledger. No old9806 stream coefficient is asserted. -/
theorem initialized_public_request_fresh_below_128 {bound : Nat}
    (largeEnough : 1264811 ≤ bound) (relation : PublicRelation)
    (statement : Fin 616 → HegemonCrypto.CanonicalBytes.Byte)
    (salt : Fin 32 → HegemonCrypto.CanonicalBytes.Byte)
    (hashMt : DigestRegister) (binding : Fin 77 → Goldilocks)
    (decsGamma : NativePrivateSpendQ58CurrentRowBoundary.Gamma) (pending : Bool)
    (labels : Index → DigestRegister)
    (next : Except String PublicResult → MixedProgram (CurrentFullRawInput bound) Work)
    (remaining : ∀ result, InputMassAtMost (2 ^ 512 : ℝ≥0∞)⁻¹ (next result))
    (ghhm : V8Smz9HonestWholeViewGames.ExternalAdaptiveReprogramming
      (Input := CurrentFullRawInput bound) (Work := Work))
    (queries : Nat)
    (registers : RegisterBasis (Input := CurrentFullRawInput bound) (Phase := DigestRegister)
      (Workspace := Work) → ℂ)
    (normalized : ‖(WithLp.toLp 2 registers :
      V8Smz9HonestWholeViewGames.GameState (Input := CurrentFullRawInput bound) (Work := Work))‖ = 1)
    (queryBound : queryCount
      (publicRequest largeEnough relation statement salt hashMt binding decsGamma pending labels next) ≤ queries)
    (lifetimeBudget : queries ≤ 3 * 2^64) :
    |actualPhaseRun queries true
        (compile (publicRequest largeEnough relation statement salt hashMt binding decsGamma pending labels next) [])
        (partialRandomOracleState (Output := DigestRegister) ∅ (responseFourierRegisters registers)) -
      actualPhaseRun queries false
        (compile (publicRequest largeEnough relation statement salt hashMt binding decsGamma pending labels next) [])
        (partialRandomOracleState (Output := DigestRegister) ∅ (responseFourierRegisters registers))| <
      (2 : ℝ)^(-128 : ℤ) :=
  (initialized_public_request_fresh_bound largeEnough relation statement salt hashMt binding decsGamma
    pending labels next remaining ghhm queries registers normalized queryBound).trans_lt
      (fresh_loss_below_128 queries lifetimeBudget)

#eval IO.eprintln "INITIALIZED_PUBLIC_MODULE_EOF"

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentInitializedPublic
