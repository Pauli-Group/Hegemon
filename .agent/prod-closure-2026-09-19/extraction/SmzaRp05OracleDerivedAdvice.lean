import SmzaRp05FinalSoundness
import SmzaRp05GroupedSuffix

/-!
# Earlier-role advice constructed from one physical raw oracle

Every selected-role context uses the same literal SMZA counter frames and
the same raw oracle. The selected role only restricts which earlier roles
are visible; it does not choose a new table. The three-result decoder below
constructs the five `EarlierReadback` equations from its actual successful
return value, rather than accepting those equations as a certificate.

The remaining caller must identify the returned values with the literal
verifier's challenge variables, and lift this deterministic decoder through
the retained physical measurement instrument.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05OracleDerivedAdvice

open scoped Classical
open HegemonCrypto.CanonicalBytes
open SmzaChallengeStageTargets SmzaRp05TracePrefixes
open SmzaRp05AcceptedRoleLabels SmzaRp05AcceptedExtraction
open SmzaRp05ConditionedExecution SmzaRp05GroupedSuffix
open SmzaRp04RawMcaSampling SmzaRp04RawRoleSampling
open V8Smz9CoherentVectorMerkle V8Smz9HiddenLeafQrom
open SmzaRp05FinalSoundness
open SmzaRp05StatementNamespace SmzaQ38McaSourceBinding
open V8Smz9PiopSoundness

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false

def emptyAllAdvice (model : RelationModel) (role : Role) : AllEarlierTables model role :=
  fun _ _ _ _ => none

/-- Exact counterexample to an arbitrary-advice acceptance bridge: with
empty advice the existing event is empty on every database, independently
of the verifier's accepted bit. This is a model-interface fact, not a forged
proof or an attack on the cryptographic construction. -/
theorem empty_advice_has_no_accepted_failure_witness
    {Key Counter BaseWork : Type}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype BaseWork] [DecidableEq BaseWork]
    (model : RelationModel) (refinement : RelationRefinement model)
    (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (outerFuel innerFuel : Nat)
    (authorizedOf : BaseWork → Finset (List HegemonCrypto.CanonicalBytes.Byte))
    (workspace : SmzaRp05CurrentAdaptiveExecution.Work
      (Counter := Counter) (BaseWork := BaseWork))
    (database : HegemonCrypto.FiniteOracleDatabase.Database Key (VectorOutput Counter))
    (claims : List (Key × VectorOutput Counter)) :
    ¬ Nonempty (AcceptedFailureWitness model refinement ns keyBytes counter
      routes (emptyAllAdvice model) outerFuel innerFuel authorizedOf workspace database claims) := by
  rintro ⟨witness⟩
  have read := witness.earlier.matrixCoefficients
  rw [← witness.adviceAtStatement .piopMatrix] at read
  simp [emptyAllAdvice] at read

/-- Exact raw frame: the digest bytes are preserved, not reinterpreted as a
field vector. Opening adds the source u64 nonce word before the digest. -/
def rawRoleInput (role : Role) (target : Digest) (nonce counter : Nat) :
    V8SmzaOracleParser.RawInput :=
  let payload := if role = .piopOpening then encodeLE 8 nonce ++ List.ofFn target
    else List.ofFn target
  encodeLE 8 V8SmzaOracleParser.profileDomain.length ++
    V8SmzaOracleParser.profileDomain ++
    encodeLE 8 (roleDomain role).length ++ roleDomain role ++
    encodeLE 8 (if role = .piopOpening then 9 else 8) ++ payload ++ encodeLE 8 counter

/-- The whole full-vector cell is read from one and the same raw table. -/
def rawRoleVector
    (oracle : V8SmzaOracleParser.RawInput → DigestRegister)
    (role : Role) (target : Digest) (nonce : Nat) : VectorOutput GroupCounter :=
  fun counter => oracle (rawRoleInput role target nonce counter.val)

/-- The real capped opening policy: first successful nonce 0,...,15;
none on exhaustion. Every attempt uses the same table and full vector. -/
def oracleDecodedAt (model : RelationModel) (routes : TypedRoutes model GroupCounter)
    (oracle : V8SmzaOracleParser.RawInput → DigestRegister)
    (statement : Statement) (role : Role) (target : Digest) :
    Option (RoleOutput model statement role) :=
  match role with
  | .decsMatrix => actualDecsMatrixOutput (routes statement).decsMatrix
      (rawRoleVector oracle .decsMatrix target 0)
  | .piopMatrix => actualPiopMatrixOutput (routes statement).piopMatrix
      (rawRoleVector oracle .piopMatrix target 0)
  | .piopOpening => firstSome
      (fun nonce : Fin 16 => actualPiopOpeningOutput (routes statement).piopOpening
        (rawRoleVector oracle .piopOpening target nonce.val)) canonicalOpeningNonceOrder
  | .decsSample => actualDecsSampleOutput (routes statement).decsSample
      (rawRoleVector oracle .decsSample target 0)

def oracleAllAdvice (model : RelationModel) (routes : TypedRoutes model GroupCounter)
    (oracle : V8SmzaOracleParser.RawInput → DigestRegister)
    (selected : Role) : AllEarlierTables model selected :=
  fun statement earlier _ target => oracleDecodedAt model routes oracle statement earlier target

/-- Deterministic replay of the three earlier challenge assignments named
by the actual causal payloads. Failed raw sampling or nonce exhaustion
returns none and cannot create an `EarlierReadback` value. -/
def decodeTraceChallenges (model : RelationModel) (routes : TypedRoutes model GroupCounter)
    (oracle : V8SmzaOracleParser.RawInput → DigestRegister)
    (statement : Statement) {ns : SmzaRp05LeafNamespace.Namespace}
    {trace : SmzaRp05TracePrefixes.Trace}
    (messages : CausalPayloads ns trace) :
    Option (Coefficients × Matrix (model.width statement) × Opening) := do
  let coefficients ← oracleDecodedAt model routes oracle statement .decsMatrix
    (V8SmzaOracleParser.digestAt messages.fpp.bytes 0)
  let matrix ← oracleDecodedAt model routes oracle statement .piopMatrix
    (V8SmzaOracleParser.digestAt messages.piop.bytes 0)
  let opening ← oracleDecodedAt model routes oracle statement .piopOpening
    (V8SmzaOracleParser.digestAt messages.decs.bytes 0)
  pure (coefficients, matrix, opening)

theorem decoded_trace_supplies_earlier_readback
    (model : RelationModel) (routes : TypedRoutes model GroupCounter)
    (oracle : V8SmzaOracleParser.RawInput → DigestRegister)
    (statement : Statement) {ns : SmzaRp05LeafNamespace.Namespace}
    {trace : SmzaRp05TracePrefixes.Trace}
    (messages : CausalPayloads ns trace)
    (coefficients : Coefficients) (matrix : Matrix (model.width statement)) (opening : Opening)
    (decoded : decodeTraceChallenges model routes oracle statement messages =
      some (coefficients, matrix, opening)) :
    EarlierReadback model statement
      (fun selected => oracleAllAdvice model routes oracle selected statement)
      messages coefficients matrix opening := by
  unfold decodeTraceChallenges at decoded
  cases coefficientsRead : oracleDecodedAt model routes oracle statement .decsMatrix
      (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) with
  | none => simp [coefficientsRead] at decoded
  | some observedCoefficients =>
      cases matrixRead : oracleDecodedAt model routes oracle statement .piopMatrix
          (V8SmzaOracleParser.digestAt messages.piop.bytes 0) with
      | none => simp [coefficientsRead, matrixRead] at decoded
      | some observedMatrix =>
          cases openingRead : oracleDecodedAt model routes oracle statement .piopOpening
              (V8SmzaOracleParser.digestAt messages.decs.bytes 0) with
          | none => simp [coefficientsRead, matrixRead, openingRead] at decoded
          | some observedOpening =>
              simp [coefficientsRead, matrixRead, openingRead] at decoded
              rcases decoded with ⟨rfl, rfl, rfl⟩
              exact ⟨coefficientsRead, coefficientsRead, matrixRead,
                coefficientsRead, openingRead⟩

end
end HegemonCrypto.SmallWood.SmzaRp05OracleDerivedAdvice
