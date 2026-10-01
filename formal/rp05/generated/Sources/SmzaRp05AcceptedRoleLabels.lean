import SmzaRp05AcceptedExtraction
import SmzaRp05CurrentRoleLabels
import HegemonCrypto.CmsAdaptiveClaimBridge
import SmzaRawTraceDepth

/-!
# Accepted RP05 failures use the labels decoded from the current v2 trace

This is the deterministic bridge between `calculatedLabels` and the physical
`currentRoleEvent`.  It is relation-generic: no RP04 program, batching width,
or public context occurs here.

The readback hypotheses in the final theorem are literal equalities returned
by the two current least-preimage decoders.  The conclusion is not supplied as
a hypothesis: an accepted extraction failure is first classified by
`SmzaRp05AcceptedExtraction`, its selected label component is identified from
the decoded v2 trace below, and the retained vector is finally exhibited as a
populated cell of `currentRoleEvent`.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedRoleLabels

open scoped Classical
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.CmsOracleDatabaseBridge
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsAdaptiveClaimBridge
open V8Smz9CoherentMerkleGeometry V8Smz9CoherentVectorMerkle
open V8Smz9CoherentMerkleInstrument
open V8Smz9PiopSoundness
open V8SmzaOnlineParser SmzaChallengeStageTargets
open SmzaRp04StatementRecordFilter SmzaRp04AuthorizedLabelTransport
open SmzaRp04ChronologicalAlgebra
open SmzaRp04RawRoleSampling SmzaRp04RawMcaSampling
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction
open SmzaRawTraceDepth SmzaRecordedTracePath
open SmzaRp05LeafNamespace SmzaRp05FilteredReadback
open SmzaRp05FilteredDecoderInstability SmzaRp05TracePrefixes
open SmzaRp05StatementNamespace
open SmzaRp05CurrentRoleLabels SmzaRp05AdaptiveDynamicBad
open SmzaRp05AcceptedExtraction

local notation "Trace" => SmzaRp05TracePrefixes.Trace
local notation "Statement" => SmzaRp05StatementNamespace.Statement
local notation "Payload" => SmzaRp05TracePrefixes.Payload

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  SmzaRp05CurrentRoleLabels.currentRawInputDecidableEq

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev Records := V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest

/-- The four causal views are subtraces of one current DECS wrapper trace.
The selected role never sees its own output in this construction. -/
def causalTrace (trace : Trace) : Role → Trace
  | .decsMatrix => child (child (child trace 0) 0) 0
  | .piopMatrix => child (child trace 0) 0
  | .piopOpening => child trace 0
  | .decsSample => trace

/-- Exact payload facts read from one current globally-normalized v2 trace.
These are byte/parser facts, not equalities of bad events. -/
structure CausalPayloads (leafNs : Namespace) (trace : Trace) where
  decs : Payload
  piop : Payload
  fpp : Payload
  decsRead : payload leafNs .decs trace = some decs
  piopRead : payload leafNs .piop (child trace 0) = some piop
  fppRead : payload leafNs .fpp (child (child trace 0) 0) = some fpp

/-! ## Current-parser recorded-prefix readback -/

theorem global_edge_decreases_depth (leafNs : Namespace)
    (stage : V8SmzaOracleParser.Stage) (input : RawInput)
    (edges : List (V8SmzaOracleParser.Stage × RawDigest))
    (parsed : globalOnlineNext leafNs stage input = some edges)
    (edge : V8SmzaOracleParser.Stage × RawDigest) (member : edge ∈ edges) :
    stageDepth edge.1 < stageDepth stage := by
  unfold globalOnlineNext at parsed
  cases decoded : globalNormalizedPayload leafNs input with
  | none => simp [decoded] at parsed
  | some message =>
      exact payload_edge_decreases_depth stage message edges
        (by simpa [decoded] using parsed) edge member

theorem global_sufficient_fuel_same_trace (leafNs : Namespace)
    (records : Records) (leftFuel rightFuel : Nat)
    (stage : V8SmzaOracleParser.Stage) (target : RawDigest)
    (leftEnough : stageDepth stage ≤ leftFuel)
    (rightEnough : stageDepth stage ≤ rightFuel) :
    extract (globalOnlineNext leafNs) records leftFuel stage target =
      extract (globalOnlineNext leafNs) records rightFuel stage target := by
  induction leftFuel generalizing rightFuel stage target with
  | zero => have positive := stage_depth_positive stage; omega
  | succ leftFuel ih =>
      cases rightFuel with
      | zero => have positive := stage_depth_positive stage; omega
      | succ rightFuel =>
          cases selected : selectedInput (globalOnlineNext leafNs) records stage target with
          | none => simp only [V8Smz9CoherentMerkleGeometry.extract, selected]
          | some input =>
              cases parsed : globalOnlineNext leafNs stage input with
              | none => simp only [V8Smz9CoherentMerkleGeometry.extract, selected, parsed]
              | some edges =>
                  simp only [V8Smz9CoherentMerkleGeometry.extract, selected, parsed]
                  apply congrArg (ExtractionTrace.record input)
                  apply List.map_congr_left
                  intro edge member
                  have decreases := global_edge_decreases_depth leafNs stage input
                    edges parsed edge member
                  exact ih rightFuel edge.1 edge.2 (by omega) (by omega)

theorem global_recorded_single_child_trace (leafNs : Namespace)
    (records : Records) (collisionFree : RecordsCollisionFree records)
    (stage childStage : V8SmzaOracleParser.Stage)
    (target childTarget : RawDigest) (input : RawInput)
    (recorded : (input, target) ∈ records)
    (parsed : globalOnlineNext leafNs stage input =
      some [(childStage, childTarget)])
    (fuel : Nat) (enough : stageDepth stage ≤ fuel) :
    extract (globalOnlineNext leafNs) records fuel stage target =
      .record input
        [extract (globalOnlineNext leafNs) records fuel childStage childTarget] := by
  have selected := selected_input_of_recorded (globalOnlineNext leafNs) records
    collisionFree stage target input recorded (by simp [parsed])
  have decreases := global_edge_decreases_depth leafNs stage input
    [(childStage, childTarget)] parsed (childStage, childTarget) (by simp)
  have decreases' : stageDepth childStage < stageDepth stage := by
    simpa using decreases
  cases fuel with
  | zero => have positive := stage_depth_positive stage; omega
  | succ fuel =>
      rw [V8Smz9CoherentMerkleGeometry.extract]
      simp only [selected, parsed, List.map_cons, List.map_nil]
      rw [global_sufficient_fuel_same_trace leafNs records fuel (fuel + 1)
        childStage childTarget (by omega) (by omega)]

theorem global_recorded_decs_chain (leafNs : Namespace)
    (records : Records) (collisionFree : RecordsCollisionFree records)
    (decsTarget piopTarget fppTarget rootTarget : RawDigest)
    (decsInput piopInput fppInput : RawInput)
    (decsRecorded : (decsInput, decsTarget) ∈ records)
    (piopRecorded : (piopInput, piopTarget) ∈ records)
    (fppRecorded : (fppInput, fppTarget) ∈ records)
    (decsNext : globalOnlineNext leafNs .decs decsInput =
      some [(.piop, piopTarget)])
    (piopNext : globalOnlineNext leafNs .piop piopInput =
      some [(.fpp, fppTarget)])
    (fppNext : globalOnlineNext leafNs .fpp fppInput =
      some [(.root, rootTarget)])
    (fuel : Nat) (enough : 28 ≤ fuel) :
    extract (globalOnlineNext leafNs) records fuel .decs decsTarget =
      .record decsInput [.record piopInput [.record fppInput
        [extract (globalOnlineNext leafNs) records fuel .root rootTarget]]] := by
  rw [global_recorded_single_child_trace leafNs records collisionFree .decs
    .piop decsTarget piopTarget decsInput decsRecorded decsNext fuel enough]
  rw [global_recorded_single_child_trace leafNs records collisionFree .piop
    .fpp piopTarget fppTarget piopInput piopRecorded piopNext fuel
    (by simp [stageDepth]; omega)]
  rw [global_recorded_single_child_trace leafNs records collisionFree .fpp
    .root fppTarget rootTarget fppInput fppRecorded fppNext fuel
    (by simp [stageDepth]; omega)]

/-- The four independent current decoders are exactly the four causal
subtraces of the recorded DECS chain.  This discharges `innerReadback` from
record membership and parser edges, rather than assuming decoder recovery. -/
theorem current_inner_readback_of_recorded_chain (leafNs : Namespace)
    (records : Records) (collisionFree : RecordsCollisionFree records)
    (decsTarget piopTarget fppTarget rootTarget : RawDigest)
    (decsInput piopInput fppInput : RawInput)
    (decsRecorded : (decsInput, decsTarget) ∈ records)
    (piopRecorded : (piopInput, piopTarget) ∈ records)
    (fppRecorded : (fppInput, fppTarget) ∈ records)
    (decsNext : globalOnlineNext leafNs .decs decsInput =
      some [(.piop, piopTarget)])
    (piopNext : globalOnlineNext leafNs .piop piopInput =
      some [(.fpp, fppTarget)])
    (fppNext : globalOnlineNext leafNs .fpp fppInput =
      some [(.root, rootTarget)])
    (fuel : Nat) (enough : 28 ≤ fuel)
    (target : Role → V8SmzaOracleParser.Stage × RawDigest)
    (targets : target .decsMatrix = (.root, rootTarget) ∧
      target .piopMatrix = (.fpp, fppTarget) ∧
      target .piopOpening = (.piop, piopTarget) ∧
      target .decsSample = (.decs, decsTarget)) :
    let trace := extract (globalOnlineNext leafNs) records fuel .decs decsTarget
    ∀ role, extract (globalOnlineNext leafNs) records fuel
        (target role).1 (target role).2 = causalTrace trace role := by
  intro trace role
  have chain := global_recorded_decs_chain leafNs records collisionFree
    decsTarget piopTarget fppTarget rootTarget decsInput piopInput fppInput
    decsRecorded piopRecorded fppRecorded decsNext piopNext fppNext fuel enough
  have fppChain := global_recorded_single_child_trace leafNs records collisionFree
    .fpp .root fppTarget rootTarget fppInput fppRecorded fppNext fuel
    (by simp [stageDepth]; omega)
  have piopChain := global_recorded_single_child_trace leafNs records collisionFree
    .piop .fpp piopTarget fppTarget piopInput piopRecorded piopNext fuel
    (by simp [stageDepth]; omega)
  cases role <;> simp [targets.1, targets.2.1, targets.2.2.1,
    targets.2.2.2, trace, causalTrace, child, chain, piopChain, fppChain]

theorem global_payload_of_recorded_input (leafNs : Namespace)
    (records : Records) (collisionFree : RecordsCollisionFree records)
    (stage : V8SmzaOracleParser.Stage) (target : RawDigest)
    (input : RawInput) (message : Payload)
    (recorded : (input, target) ∈ records)
    (parsed : globalNormalizedPayload leafNs input = some message)
    (valid : (V8SmzaOnlineParser.payloadNext stage message).isSome)
    (fuel : Nat) (positive : 0 < fuel) :
    payload leafNs message.kind
      (extract (globalOnlineNext leafNs) records fuel stage target) = some message := by
  have nextValid : (globalOnlineNext leafNs stage input).isSome := by
    simpa [globalOnlineNext, parsed] using valid
  have selected := selected_input_of_recorded (globalOnlineNext leafNs) records
    collisionFree stage target input recorded nextValid
  obtain ⟨edges, next⟩ := Option.isSome_iff_exists.mp nextValid
  cases fuel with
  | zero => omega
  | succ fuel =>
      simp [V8Smz9CoherentMerkleGeometry.extract, selected, next, payload, parsed]

/-- The nonleaf decoder selects the actual current statement from the
recorded root/FPP wrapper bytes.  Its conclusion is uniform in the selected
role and follows from the same recorded chain as the inner decoder. -/
theorem current_outer_readback_of_recorded_chain (leafNs : Namespace)
    (records : Records) (collisionFree : RecordsCollisionFree records)
    (decsTarget piopTarget fppTarget rootTarget : RawDigest)
    (decsInput piopInput fppInput rootInput : RawInput)
    (decs piop fpp root : Payload)
    (decsRecorded : (decsInput, decsTarget) ∈ records)
    (piopRecorded : (piopInput, piopTarget) ∈ records)
    (fppRecorded : (fppInput, fppTarget) ∈ records)
    (rootRecorded : (rootInput, rootTarget) ∈ records)
    (decsParsed : globalNormalizedPayload leafNs decsInput = some decs)
    (piopParsed : globalNormalizedPayload leafNs piopInput = some piop)
    (fppParsed : globalNormalizedPayload leafNs fppInput = some fpp)
    (rootParsed : globalNormalizedPayload leafNs rootInput = some root)
    (_decsKind : decs.kind = .decs) (_piopKind : piop.kind = .piop)
    (fppKind : fpp.kind = .fpp) (rootKind : root.kind = .root)
    (decsNext : globalOnlineNext leafNs .decs decsInput =
      some [(.piop, piopTarget)])
    (piopNext : globalOnlineNext leafNs .piop piopInput =
      some [(.fpp, fppTarget)])
    (fppNext : globalOnlineNext leafNs .fpp fppInput =
      some [(.root, rootTarget)])
    (rootValid : (V8SmzaOnlineParser.payloadNext .root root).isSome)
    (statementBytes : List Byte)
    (rootStatement : root.bytes.drop 96 = statementBytes)
    (fppStatement : fpp.bytes.drop 16304 = statementBytes)
    (rootCanonical : leafNs.canonicalPreamble statementBytes = true)
    (fppCanonical : leafNs.canonicalPreamble statementBytes = true)
    (fuel : Nat) (enough : 28 ≤ fuel)
    (target : Role → V8SmzaOracleParser.Stage × RawDigest)
    (targets : target .decsMatrix = (.root, rootTarget) ∧
      target .piopMatrix = (.fpp, fppTarget) ∧
      target .piopOpening = (.piop, piopTarget) ∧
      target .decsSample = (.decs, decsTarget)) :
    ∀ role, preambleFromTrace leafNs role
        (extract (globalOnlineNext leafNs) records fuel
          (target role).1 (target role).2) = some statementBytes := by
  have chain := global_recorded_decs_chain leafNs records collisionFree
    decsTarget piopTarget fppTarget rootTarget decsInput piopInput fppInput
    decsRecorded piopRecorded fppRecorded decsNext piopNext fppNext fuel enough
  have rootRead := global_payload_of_recorded_input leafNs records collisionFree
    .root rootTarget rootInput root rootRecorded rootParsed rootValid fuel (by omega)
  have fppValid : (V8SmzaOnlineParser.payloadNext .fpp fpp).isSome := by
    have next : V8SmzaOnlineParser.payloadNext .fpp fpp =
        some [(.root, rootTarget)] := by
      simpa [globalOnlineNext, fppParsed] using fppNext
    simp [next]
  have fppRead := global_payload_of_recorded_input leafNs records collisionFree
    .fpp fppTarget fppInput fpp fppRecorded fppParsed fppValid fuel (by omega)
  have piopValid : (V8SmzaOnlineParser.payloadNext .piop piop).isSome := by
    have next : V8SmzaOnlineParser.payloadNext .piop piop =
        some [(.fpp, fppTarget)] := by
      simpa [globalOnlineNext, piopParsed] using piopNext
    simp [next]
  have piopRead := global_payload_of_recorded_input leafNs records collisionFree
    .piop piopTarget piopInput piop piopRecorded piopParsed piopValid fuel (by omega)
  have decsValid : (V8SmzaOnlineParser.payloadNext .decs decs).isSome := by
    have next : V8SmzaOnlineParser.payloadNext .decs decs =
        some [(.piop, piopTarget)] := by
      simpa [globalOnlineNext, decsParsed] using decsNext
    simp [next]
  have decsRead := global_payload_of_recorded_input leafNs records collisionFree
    .decs decsTarget decsInput decs decsRecorded decsParsed decsValid fuel (by omega)
  have rootRead' : payload leafNs .root
      (extract (globalOnlineNext leafNs) records fuel .root rootTarget) = some root := by
    simpa [rootKind] using rootRead
  have fppRead' : payload leafNs .fpp
      (extract (globalOnlineNext leafNs) records fuel .fpp fppTarget) = some fpp := by
    simpa [fppKind] using fppRead
  have fppChain := global_recorded_single_child_trace leafNs records collisionFree
    .fpp .root fppTarget rootTarget fppInput fppRecorded fppNext fuel
    (by simp [stageDepth]; omega)
  have piopChain := global_recorded_single_child_trace leafNs records collisionFree
    .piop .fpp piopTarget fppTarget piopInput piopRecorded piopNext fuel
    (by simp [stageDepth]; omega)
  have fppReadRecord : payload leafNs .fpp
      (.record fppInput [extract (globalOnlineNext leafNs) records fuel
        .root rootTarget]) = some fpp := by
    rw [← fppChain]
    exact fppRead'
  intro role
  cases role
  · simp [preambleFromTrace, targets.1, rootRead', rootStatement, rootCanonical]
  · simp [preambleFromTrace, targets.2.1, fppRead', fppStatement, fppCanonical]
  · simp [preambleFromTrace, targets.2.2.1, piopChain, child,
      fppRead', fppStatement, fppCanonical]
  · simp [preambleFromTrace, targets.2.2.2, chain, child,
      fppReadRecord, fppStatement, fppCanonical]

/-- Construct the exact payload package used by the label theorem directly
from the recorded current-parser chain. -/
def causal_payloads_of_recorded_chain (leafNs : Namespace)
    (records : Records) (collisionFree : RecordsCollisionFree records)
    (decsTarget piopTarget fppTarget rootTarget : RawDigest)
    (decsInput piopInput fppInput : RawInput) (decs piop fpp : Payload)
    (decsRecorded : (decsInput, decsTarget) ∈ records)
    (piopRecorded : (piopInput, piopTarget) ∈ records)
    (fppRecorded : (fppInput, fppTarget) ∈ records)
    (decsParsed : globalNormalizedPayload leafNs decsInput = some decs)
    (piopParsed : globalNormalizedPayload leafNs piopInput = some piop)
    (fppParsed : globalNormalizedPayload leafNs fppInput = some fpp)
    (decsKind : decs.kind = .decs) (piopKind : piop.kind = .piop)
    (fppKind : fpp.kind = .fpp)
    (decsNext : globalOnlineNext leafNs .decs decsInput =
      some [(.piop, piopTarget)])
    (piopNext : globalOnlineNext leafNs .piop piopInput =
      some [(.fpp, fppTarget)])
    (fppNext : globalOnlineNext leafNs .fpp fppInput =
      some [(.root, rootTarget)])
    (fuel : Nat) (enough : 28 ≤ fuel) :
    CausalPayloads leafNs
      (extract (globalOnlineNext leafNs) records fuel .decs decsTarget) := by
  have chain := global_recorded_decs_chain leafNs records collisionFree
    decsTarget piopTarget fppTarget rootTarget decsInput piopInput fppInput
    decsRecorded piopRecorded fppRecorded decsNext piopNext fppNext fuel enough
  have piopChain := global_recorded_single_child_trace leafNs records collisionFree
    .piop .fpp piopTarget fppTarget piopInput piopRecorded piopNext fuel
    (by simp [stageDepth]; omega)
  have fppChain := global_recorded_single_child_trace leafNs records collisionFree
    .fpp .root fppTarget rootTarget fppInput fppRecorded fppNext fuel
    (by simp [stageDepth]; omega)
  have decsValid : (V8SmzaOnlineParser.payloadNext .decs decs).isSome := by
    have next : V8SmzaOnlineParser.payloadNext .decs decs =
        some [(.piop, piopTarget)] := by
      simpa [globalOnlineNext, decsParsed] using decsNext
    simp [next]
  have piopValid : (V8SmzaOnlineParser.payloadNext .piop piop).isSome := by
    have next : V8SmzaOnlineParser.payloadNext .piop piop =
        some [(.fpp, fppTarget)] := by
      simpa [globalOnlineNext, piopParsed] using piopNext
    simp [next]
  have fppValid : (V8SmzaOnlineParser.payloadNext .fpp fpp).isSome := by
    have next : V8SmzaOnlineParser.payloadNext .fpp fpp =
        some [(.root, rootTarget)] := by
      simpa [globalOnlineNext, fppParsed] using fppNext
    simp [next]
  have decsRead := global_payload_of_recorded_input leafNs records collisionFree
    .decs decsTarget decsInput decs decsRecorded decsParsed decsValid fuel (by omega)
  have piopRead := global_payload_of_recorded_input leafNs records collisionFree
    .piop piopTarget piopInput piop piopRecorded piopParsed piopValid fuel (by omega)
  have fppRead := global_payload_of_recorded_input leafNs records collisionFree
    .fpp fppTarget fppInput fpp fppRecorded fppParsed fppValid fuel (by omega)
  refine ⟨decs, piop, fpp, ?_, ?_, ?_⟩
  · simpa [decsKind] using decsRead
  · have readRecord : payload leafNs .piop
        (.record piopInput [extract (globalOnlineNext leafNs) records fuel
          .fpp fppTarget]) = some piop := by
      rw [← piopChain]
      simpa [piopKind] using piopRead
    rw [fppChain] at readRecord
    simpa [chain, child] using readRecord
  · have readRecord : payload leafNs .fpp
        (.record fppInput [extract (globalOnlineNext leafNs) records fuel
          .root rootTarget]) = some fpp := by
      rw [← fppChain]
      simpa [fppKind] using fppRead
    simpa [chain, child, fppChain] using readRecord

def causalOracle (leafNs : Namespace) (trace : Trace) : CommittedOracle :=
  rootOracle leafNs (causalTrace trace .decsMatrix)

/-- Only the component inspected by the selected role is relevant. -/
def SameRolePrefix {width : Nat} (role : Role)
    (left right : Prefix width) : Prop :=
  match role with
  | .decsMatrix => left.decsMatrix = right.decsMatrix
  | .piopMatrix => left.piopMatrix = right.piopMatrix
  | .piopOpening => left.piopOpening = right.piopOpening
  | .decsSample =>
      left.smallSupport = right.smallSupport ∧ left.lvcs = right.lvcs

theorem complete_bad_congr_role_prefix
    {Counter : Type*} {width : Nat}
    (routes : Routes Counter width) (role : Role)
    (left right : Prefix width) (vector : VectorOutput Counter)
    (same : SameRolePrefix role left right) :
    completeBad routes role left vector ↔ completeBad routes role right vector := by
  cases role <;> simp_all [SameRolePrefix, completeBad]

theorem typed_complete_bad_congr_role_prefix
    {Counter : Type*} (model : RelationModel)
    (routes : TypedRoutes model Counter) (statement : Statement) (role : Role)
    (left right : Prefix (model.width statement))
    (vector : VectorOutput Counter) (same : SameRolePrefix role left right) :
    typedCompleteRawBad model routes role (.decoded statement left) vector ↔
      typedCompleteRawBad model routes role (.decoded statement right) vector := by
  exact complete_bad_congr_role_prefix (routes statement) role left right vector same

/-- Strictly-earlier retained table values used by the causal prefix. -/
structure EarlierReadback (model : RelationModel) (statement : Statement)
    (advice : (role : Role) → EarlierTables model statement role)
    {leafNs : Namespace} {trace : Trace}
    (messages : CausalPayloads leafNs trace)
    (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) : Prop where
  matrixCoefficients : advice .piopMatrix .decsMatrix (by decide)
      (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) = some coefficients
  openingCoefficients : advice .piopOpening .decsMatrix (by decide)
      (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) = some coefficients
  openingMatrix : advice .piopOpening .piopMatrix (by decide)
      (V8SmzaOracleParser.digestAt messages.piop.bytes 0) = some matrix
  sampleCoefficients : advice .decsSample .decsMatrix (by decide)
      (V8SmzaOracleParser.digestAt messages.fpp.bytes 0) = some coefficients
  sampleOpening : advice .decsSample .piopOpening (by decide)
      (V8SmzaOracleParser.digestAt messages.decs.bytes 0) = some opening

/-- Causal strategy made from the actual recorded PIOP response and the
actual post-opening verifier message.  Only the DECS-transmitted coefficient
field is replaced by its literal decoder; all heads, masks, partials, highs,
and corrections remain the verifier's recorded values. -/
def traceOpeningMessage (decs : Payload) (message : OpeningMessage) : OpeningMessage :=
  { message with claimedCoefficients := queryCoefficients decs }

def traceStrategy (model : RelationModel) (statement : Statement)
    (piop decs : Payload) (message : OpeningMessage) : Strategy model statement where
  piopResponse _ _ := piopResponse piop
  afterOpening _ _ _ := traceOpeningMessage decs message

theorem trace_strategy_piop_response (model : RelationModel) (statement : Statement)
    (piop decs : Payload) (message : OpeningMessage)
    (coefficients : Coefficients) (matrix : Matrix (model.width statement)) :
    (traceStrategy model statement piop decs message).piopResponse
      coefficients matrix = piopResponse piop := rfl

theorem trace_strategy_claimed_coefficients
    (model : RelationModel) (statement : Statement)
    (piop decs : Payload) (message : OpeningMessage)
    (coefficients : Coefficients) (matrix : Matrix (model.width statement))
    (opening : Opening) :
    ((traceStrategy model statement piop decs message).afterOpening
      coefficients matrix opening).claimedCoefficients = queryCoefficients decs := rfl

theorem matrix_label_of_earlier_readback
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads leafNs trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (coefficients : Coefficients) (matrix : Matrix (model.width statement))
    (opening : Opening)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening) :
    matrixLabel model leafNs statement (advice .piopMatrix)
        (causalTrace trace .piopMatrix) =
      matrixPrefix model leafNs statement
        (causalTrace trace .decsMatrix) messages.fpp coefficients := by
  unfold matrixLabel
  dsimp [causalTrace, Bind.bind, Option.bind, RoleOutput]
  rw [messages.fppRead]
  dsimp [Bind.bind, Option.bind, RoleOutput]
  rw [earlier.matrixCoefficients]

theorem calculated_matrix_eq_prefix
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (trace : Trace) (fpp : Payload)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) :
    (calculatedLabels statement (causalOracle leafNs trace)
        (sourceResponse fpp) strategy coefficients matrix opening).piopMatrix =
      matrixPrefix model leafNs statement
        (causalTrace trace .decsMatrix) fpp coefficients := by
  unfold calculatedLabels matrixPrefix
  dsimp [causalOracle, causalTrace, recoveredSource]

theorem causal_matrix_prefix_matches_calculated
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads leafNs trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening) :
    SameRolePrefix .piopMatrix
      (prefixLabels model leafNs statement .piopMatrix (advice .piopMatrix)
        (causalTrace trace .piopMatrix))
      (calculatedLabels statement (causalOracle leafNs trace)
        (sourceResponse messages.fpp) strategy coefficients matrix opening) := by
  simp only [SameRolePrefix, prefixLabels]
  rw [matrix_label_of_earlier_readback model leafNs statement trace
    messages advice coefficients matrix opening earlier]
  exact (calculated_matrix_eq_prefix model leafNs statement trace
    messages.fpp strategy coefficients matrix opening).symm

theorem causal_opening_prefix_matches_calculated
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads leafNs trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening)
    (piopResponseRead : strategy.piopResponse coefficients matrix =
      piopResponse messages.piop) :
    SameRolePrefix .piopOpening
      (prefixLabels model leafNs statement .piopOpening (advice .piopOpening)
        (causalTrace trace .piopOpening))
      (calculatedLabels statement (causalOracle leafNs trace)
        (sourceResponse messages.fpp) strategy coefficients matrix opening) := by
  simp only [SameRolePrefix, prefixLabels]
  unfold openingLabel
  dsimp [causalTrace, Bind.bind, Option.bind, RoleOutput]
  rw [messages.piopRead, messages.fppRead]
  dsimp [Bind.bind, Option.bind, RoleOutput]
  rw [earlier.openingCoefficients, earlier.openingMatrix]
  dsimp [Bind.bind, Option.bind, RoleOutput, openingPrefix,
    recoveredSource, calculatedLabels, causalOracle]
  rw [piopResponseRead]
  rfl

theorem causal_sample_support_eq
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads leafNs trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening)
    (_claimedCoefficientsRead :
      (strategy.afterOpening coefficients matrix opening).claimedCoefficients =
        queryCoefficients messages.decs) :
    (prefixLabels model leafNs statement .decsSample (advice .decsSample)
      (causalTrace trace .decsSample)).smallSupport =
      (calculatedLabels statement (causalOracle leafNs trace)
        (sourceResponse messages.fpp) strategy coefficients matrix opening).smallSupport := by
  simp only [prefixLabels]
  unfold queryLabels
  dsimp [causalTrace, Bind.bind, Option.bind, RoleOutput]
  rw [messages.decsRead, messages.piopRead, messages.fppRead]
  dsimp [Bind.bind, Option.bind, RoleOutput]
  rw [earlier.sampleCoefficients, earlier.sampleOpening]
  dsimp [Bind.bind, Option.bind, RoleOutput, calculatedLabels, causalOracle]
  simp only [causalTrace]

theorem causal_sample_lvcs_eq
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads leafNs trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening)
    (claimedCoefficientsRead :
      (strategy.afterOpening coefficients matrix opening).claimedCoefficients =
        queryCoefficients messages.decs) :
    (prefixLabels model leafNs statement .decsSample (advice .decsSample)
      (causalTrace trace .decsSample)).lvcs =
      (calculatedLabels statement (causalOracle leafNs trace)
        (sourceResponse messages.fpp) strategy coefficients matrix opening).lvcs := by
  simp only [prefixLabels]
  unfold queryLabels
  dsimp [causalTrace, Bind.bind, Option.bind, RoleOutput]
  rw [messages.decsRead, messages.piopRead, messages.fppRead]
  dsimp [Bind.bind, Option.bind, RoleOutput]
  rw [earlier.sampleCoefficients, earlier.sampleOpening]
  dsimp [Bind.bind, Option.bind, RoleOutput, calculatedLabels, causalOracle]
  rw [claimedCoefficientsRead]
  simp only [causalTrace, recoveredSource]

theorem causal_sample_prefix_matches_calculated
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads leafNs trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening)
    (claimedCoefficientsRead :
      (strategy.afterOpening coefficients matrix opening).claimedCoefficients =
        queryCoefficients messages.decs) :
    SameRolePrefix .decsSample
      (prefixLabels model leafNs statement .decsSample (advice .decsSample)
        (causalTrace trace .decsSample))
      (calculatedLabels statement (causalOracle leafNs trace)
        (sourceResponse messages.fpp) strategy coefficients matrix opening) := by
  exact ⟨causal_sample_support_eq model leafNs statement trace messages advice
    strategy coefficients matrix opening earlier claimedCoefficientsRead,
    causal_sample_lvcs_eq model leafNs statement trace messages advice
      strategy coefficients matrix opening earlier claimedCoefficientsRead⟩

/-- The current trace prefix has exactly the selected chronological component
used by accepted extraction.  The two message equalities are literal parser
readback from the PIOP and DECS wrappers. -/
theorem causal_role_prefix_matches_calculated
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads leafNs trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening)
    (piopResponseRead : strategy.piopResponse coefficients matrix =
      piopResponse messages.piop)
    (claimedCoefficientsRead :
      (strategy.afterOpening coefficients matrix opening).claimedCoefficients =
        queryCoefficients messages.decs)
    (role : Role) :
    SameRolePrefix role
      (prefixLabels model leafNs statement role (advice role)
        (causalTrace trace role))
      (calculatedLabels statement (causalOracle leafNs trace)
        (sourceResponse messages.fpp) strategy coefficients matrix opening) := by
  cases role with
  | decsMatrix =>
      rfl
  | piopMatrix =>
      exact causal_matrix_prefix_matches_calculated model leafNs statement
        trace messages advice strategy coefficients matrix opening earlier
  | piopOpening =>
      exact causal_opening_prefix_matches_calculated model leafNs statement
        trace messages advice strategy coefficients matrix opening earlier
        piopResponseRead
  | decsSample =>
      exact causal_sample_prefix_matches_calculated model leafNs statement
        trace messages advice strategy coefficients matrix opening earlier
        claimedCoefficientsRead

theorem causal_role_prefix_matches_trace_strategy
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (trace : Trace) (messages : CausalPayloads leafNs trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (message : OpeningMessage) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening) (role : Role) :
    SameRolePrefix role
      (prefixLabels model leafNs statement role (advice role)
        (causalTrace trace role))
      (calculatedLabels statement (causalOracle leafNs trace)
        (sourceResponse messages.fpp)
        (traceStrategy model statement messages.piop messages.decs message)
        coefficients matrix opening) := by
  exact causal_role_prefix_matches_calculated model leafNs statement trace
    messages advice
    (traceStrategy model statement messages.piop messages.decs message)
    coefficients matrix opening earlier
    (trace_strategy_piop_response model statement messages.piop messages.decs
      message coefficients matrix)
    (trace_strategy_claimed_coefficients model statement messages.piop messages.decs
      message coefficients matrix opening) role

/-- Total byte postprocessing returns the finite statement carried by the
accepted transcript. -/
theorem role_labels_from_statement_bytes
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (role : Role) (advice : AllEarlierTables model role) (trace : Trace) :
    roleLabelsFromBytes model leafNs role advice statement.toBytes trace =
      .decoded statement
        (prefixLabels model leafNs statement role (advice statement) trace) := by
  have length : statement.toBytes.length = preambleBytes :=
    SmzaRp05StatementNamespace.Statement.toBytes_length statement
  have roundtrip : statementOfBytes statement.toBytes length = statement := by
    exact SmzaRp05StatementNamespace.Statement.toBytes_injective
      (statement_of_bytes_roundtrip statement.toBytes length)
  simp [roleLabelsFromBytes, statementOfBytes?, length, roundtrip, roleLabels]

theorem authorized_bad_of_readback
    {Target Label Cell : Type*}
    (leafStatement : StatementParser RawInput (List Byte))
    (outer : Records → Target → Option (List Byte))
    (fullLabel : List Byte → Records → Target → Label)
    (authorized : Finset (List Byte)) (records : Records) (target : Target)
    (statement : List Byte) (cell : Cell)
    (bad : List Byte → Label → Cell → Prop)
    (read : outer (nonleafFilter leafStatement records) target = some statement)
    (fresh : statement ∉ authorized)
    (witness : bad statement
      (fullLabel statement
        (oneStatementFilter leafStatement statement records) target) cell) :
    AuthorizedBad bad
      (completeFilteredLabel leafStatement outer fullLabel authorized records target)
      cell := by
  simp [completeFilteredLabel, read, fresh, AuthorizedBad]
  exact witness

/-- The literal deterministic inclusion consumed by partial readout.

`outerReadback` and `innerReadback` are exact results of the current nonleaf
and statement-filtered least-preimage decoders on `rawRecords database`; they
do not mention `currentRoleEvent`, `DynamicBad`, or extraction failure.  All
earlier table values are the retained typed reads in `advice`.
-/
theorem accepted_failure_has_current_role_event
    {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (refinement : RelationRefinement model)
    (leafNs : Namespace) (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (authorized : Finset (List Byte))
    (statement : Statement) (fresh : statement.toBytes ∉ authorized)
    (outerFuel innerFuel : Nat)
    (keys : Role → Key) (vectors : Role → VectorOutput Counter)
    (database : Database Key (VectorOutput Counter))
    (trace : Trace) (messages : CausalPayloads leafNs trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (adviceAtStatement : ∀ role, allAdvice role statement = advice role)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) (query : Query)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening)
    (piopResponseRead : strategy.piopResponse coefficients matrix =
      piopResponse messages.piop)
    (claimedCoefficientsRead :
      (strategy.afterOpening coefficients matrix opening).claimedCoefficients =
        queryCoefficients messages.decs)
    (roleQueries : ∀ role, ∃ parsed,
      parseStageQuery (keyBytes (keys role)) = some parsed ∧ parsed.role = role)
    (recorded : ∀ role, database (keys role) = some (vectors role))
    (outerReadback : ∀ role,
      currentOuter leafNs keyBytes role outerFuel
        (nonleafFilter (globalLeafStatement leafNs)
          (rawRecords keyBytes (vectorOutputBytes counter) database))
        (keys role) = some statement.toBytes)
    (innerReadback : ∀ role,
      extract (globalOnlineNext leafNs)
        (oneStatementFilter (globalLeafStatement leafNs) statement.toBytes
          (rawRecords keyBytes (vectorOutputBytes counter) database))
        innerFuel (targetOfRaw role (keyBytes (keys role))).1
          (targetOfRaw role (keyBytes (keys role))).2 = causalTrace trace role)
    (decsRead : actualDecsMatrixOutput (routes statement).decsMatrix
      (vectors .decsMatrix) = some coefficients)
    (matrixRead : actualPiopMatrixOutput (routes statement).piopMatrix
      (vectors .piopMatrix) = some matrix)
    (openingRead : actualPiopOpeningOutput (routes statement).piopOpening
      (vectors .piopOpening) = some opening)
    (queryRead : actualDecsSampleOutput (routes statement).decsSample
      (vectors .decsSample) = some query)
    (checks : AcceptedChecks refinement statement (causalOracle leafNs trace)
      (sourceResponse messages.fpp) strategy coefficients matrix opening query)
    (failed : ExtractionFailure refinement statement (causalOracle leafNs trace)
      (sourceResponse messages.fpp) coefficients) :
    ∃ role, currentRoleEvent model leafNs keyBytes counter routes role
      (allAdvice role) outerFuel innerFuel authorized database := by
  obtain ⟨role, calculatedBad⟩ :=
    accepted_failure_has_typed_complete_raw_bad_role refinement statement routes
      (causalOracle leafNs trace) (sourceResponse messages.fpp) strategy
      coefficients matrix opening query vectors decsRead matrixRead openingRead
      queryRead checks failed
  have same := causal_role_prefix_matches_calculated model leafNs statement trace
    messages advice strategy coefficients matrix opening earlier piopResponseRead
    claimedCoefficientsRead role
  have tracedBad : typedCompleteRawBad model routes role
      (.decoded statement
        (prefixLabels model leafNs statement role (advice role)
          (causalTrace trace role))) (vectors role) :=
    (typed_complete_bad_congr_role_prefix model routes statement role _ _
      (vectors role) same).mpr calculatedBad
  obtain ⟨parsed, parsedQuery, parsedRole⟩ := roleQueries role
  refine ⟨role, keys role, vectors role, recorded role, ?_, ?_⟩
  · exact ⟨parsed, parsedQuery, parsedRole⟩
  · dsimp only
    change AuthorizedBad
      (fun _ label output => typedCompleteRawBad model routes role label output)
      (completeFilteredLabel (globalLeafStatement leafNs)
        (currentOuter leafNs keyBytes role outerFuel)
        (statementTraceDecoder (globalOnlineNext leafNs)
          (fun _ key => targetOfRaw role (keyBytes key))
          (fun statement _ trace => roleLabelsFromBytes model leafNs role
            (allAdvice role) statement trace) innerFuel)
        authorized (rawRecords keyBytes (vectorOutputBytes counter) database)
        (keys role)) (vectors role)
    eapply authorized_bad_of_readback
    · exact outerReadback role
    · exact fresh
    · change typedCompleteRawBad model routes role
        (roleLabelsFromBytes model leafNs role (allAdvice role) statement.toBytes
          (extract (globalOnlineNext leafNs)
            (oneStatementFilter (globalLeafStatement leafNs) statement.toBytes
              (rawRecords keyBytes (vectorOutputBytes counter) database))
            innerFuel (targetOfRaw role (keyBytes (keys role))).1
              (targetOfRaw role (keyBytes (keys role))).2))
        (vectors role)
      rw [innerReadback role, role_labels_from_statement_bytes,
        adviceAtStatement role]
      exact tracedBad

/-- Pointwise form used by terminal partial readout.  The retained-claim
failure disjunct is derived by deciding the literal database claim event.  If
all claims are present, their membership supplies the `recorded` premise of
`accepted_failure_has_current_role_event`; no probabilistic or desired-event
inclusion is assumed. -/
theorem accepted_failure_current_event_or_claim_failure
    {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key]
    [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (refinement : RelationRefinement model)
    (leafNs : Namespace) (keyBytes : Key → RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter)
    (authorized : Finset (List Byte))
    (statement : Statement) (fresh : statement.toBytes ∉ authorized)
    (outerFuel innerFuel : Nat)
    (keys : Role → Key) (vectors : Role → VectorOutput Counter)
    (claims : List (Key × VectorOutput Counter))
    (claimsContainRoles : ∀ role, (keys role, vectors role) ∈ claims)
    (database : Database Key (VectorOutput Counter))
    (trace : Trace) (messages : CausalPayloads leafNs trace)
    (advice : (role : Role) → EarlierTables model statement role)
    (allAdvice : (role : Role) → AllEarlierTables model role)
    (adviceAtStatement : ∀ role, allAdvice role statement = advice role)
    (strategy : Strategy model statement) (coefficients : Coefficients)
    (matrix : Matrix (model.width statement)) (opening : Opening) (query : Query)
    (earlier : EarlierReadback model statement advice messages
      coefficients matrix opening)
    (piopResponseRead : strategy.piopResponse coefficients matrix =
      piopResponse messages.piop)
    (claimedCoefficientsRead :
      (strategy.afterOpening coefficients matrix opening).claimedCoefficients =
        queryCoefficients messages.decs)
    (roleQueries : ∀ role, ∃ parsed,
      parseStageQuery (keyBytes (keys role)) = some parsed ∧ parsed.role = role)
    (outerReadback : ∀ role,
      currentOuter leafNs keyBytes role outerFuel
        (nonleafFilter (globalLeafStatement leafNs)
          (rawRecords keyBytes (vectorOutputBytes counter) database))
        (keys role) = some statement.toBytes)
    (innerReadback : ∀ role,
      extract (globalOnlineNext leafNs)
        (oneStatementFilter (globalLeafStatement leafNs) statement.toBytes
          (rawRecords keyBytes (vectorOutputBytes counter) database))
        innerFuel (targetOfRaw role (keyBytes (keys role))).1
          (targetOfRaw role (keyBytes (keys role))).2 = causalTrace trace role)
    (decsRead : actualDecsMatrixOutput (routes statement).decsMatrix
      (vectors .decsMatrix) = some coefficients)
    (matrixRead : actualPiopMatrixOutput (routes statement).piopMatrix
      (vectors .piopMatrix) = some matrix)
    (openingRead : actualPiopOpeningOutput (routes statement).piopOpening
      (vectors .piopOpening) = some opening)
    (queryRead : actualDecsSampleOutput (routes statement).decsSample
      (vectors .decsSample) = some query)
    (checks : AcceptedChecks refinement statement (causalOracle leafNs trace)
      (sourceResponse messages.fpp) strategy coefficients matrix opening query)
    (failed : ExtractionFailure refinement statement (causalOracle leafNs trace)
      (sourceResponse messages.fpp) coefficients) :
    (∃ role, currentRoleEvent model leafNs keyBytes counter routes role
      (allAdvice role) outerFuel innerFuel authorized database) ∨
      ¬ ClaimsDatabaseEvent claims database := by
  by_cases retained : ClaimsDatabaseEvent claims database
  · left
    apply accepted_failure_has_current_role_event model refinement leafNs
      keyBytes counter routes authorized statement fresh outerFuel innerFuel
      keys vectors database trace messages advice allAdvice adviceAtStatement
      strategy coefficients matrix opening query earlier piopResponseRead
      claimedCoefficientsRead roleQueries
    · intro role
      exact retained (keys role, vectors role) (claimsContainRoles role)
    · exact outerReadback
    · exact innerReadback
    · exact decsRead
    · exact matrixRead
    · exact openingRead
    · exact queryRead
    · exact checks
    · exact failed
  · exact Or.inr retained

end
end HegemonCrypto.SmallWood.SmzaRp05AcceptedRoleLabels
