import SmzaRp05AdaptiveDynamicBad
import SmzaRp05TracePrefixes
import SmzaRp05ChallengeRoleSeparation

/-! Literal RP05 outer-statement and inner-prefix functions for the direct
CMS event.  The outer pass reads the existing root/FPP context bytes.  The
inner pass reads the full statement-filtered trace, with only earlier role
tables supplied as advice.  Neither pass inspects the selected output. -/
namespace HegemonCrypto.SmallWood.SmzaRp05CurrentRoleLabels

open scoped Classical
open HegemonCrypto.CanonicalBytes
open HegemonCrypto.CmsClassicalDatabase
open HegemonCrypto.FiniteOracleDatabase
open V8Smz9CoherentVectorMerkle
open SmzaChallengeStageTargets SmzaRp05LeafNamespace
open SmzaRp05FilteredReadback SmzaRp05FilteredDecoderInstability
open SmzaRp05TracePrefixes SmzaRp05AdaptiveDynamicBad
open SmzaRp04AuthorizedLabelTransport SmzaRp04CompleteRawRoleCells
open SmzaRp04RawMcaSampling

noncomputable section
set_option autoImplicit false

@[reducible] def currentRawInputDecidableEq :
    DecidableEq V8SmzaOracleParser.RawInput :=
  (inferInstance : LinearOrder V8SmzaOracleParser.RawInput).toDecidableEq

local instance : DecidableEq V8SmzaOracleParser.RawInput :=
  currentRawInputDecidableEq

/-- The root wrapper binds the DECS-matrix role; the later three roles bind
the same preamble through the FPP wrapper at the appropriate child depth. -/
def preambleFromTrace (ns : SmzaRp05LeafNamespace.Namespace) (role : Role)
    (trace : SmzaRp05TracePrefixes.Trace) :
    Option (List Byte) := do
  let bytes ← match role with
    | .decsMatrix =>
        (SmzaRp05TracePrefixes.payload ns .root trace).map
          (fun payload => payload.bytes.drop 96)
    | .piopMatrix =>
        (SmzaRp05TracePrefixes.payload ns .fpp trace).map
          (fun payload => payload.bytes.drop 16304)
    | .piopOpening =>
        (SmzaRp05TracePrefixes.payload ns .fpp
          (SmzaRp05TracePrefixes.child trace 0)).map
          (fun payload => payload.bytes.drop 16304)
    | .decsSample =>
        (SmzaRp05TracePrefixes.payload ns .fpp
          (SmzaRp05TracePrefixes.child
            (SmzaRp05TracePrefixes.child trace 0) 0)).map
          (fun payload => payload.bytes.drop 16304)
  if ns.canonicalPreamble bytes then some bytes else none

/-- The default target is unreachable for selected-role events.  Keeping a
total function permits the raw decoder instability bound on every database,
including malformed keys, without conditioning on parser success. -/
def targetOfRaw (role : Role) (input : V8SmzaOracleParser.RawInput) :
    V8SmzaOracleParser.Stage × V8SmzaOracleParser.RawDigest :=
  (selectedTarget role input).getD (roleStage role, fun _ => 0)

theorem target_of_parsed_role (role : Role)
    (input : V8SmzaOracleParser.RawInput) (parsed : StageQuery)
    (readback : parseStageQuery input = some parsed) (sameRole : parsed.role = role) :
    targetOfRaw role input = (roleStage role, parsed.target) := by
  simp [targetOfRaw, selectedTarget, readback, sameRole]

/-- No RP04 width or program is used in either trace pass. -/
def currentOuter {Key : Type*} (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (role : Role)
    (outerFuel : Nat) : SmzaRp05AdaptiveDynamicBad.RawRecords → Key → Option (List Byte) :=
  rawTraceDecoder (globalOnlineNext ns)
    (fun key => targetOfRaw role (keyBytes key))
    (fun _ trace => preambleFromTrace ns role trace) outerFuel

def currentRoleEvent {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte)) :
    Database Key (VectorOutput Counter) → Prop :=
  roleEvent keyBytes (vectorOutputBytes counter) (globalLeafStatement ns)
    (currentOuter ns keyBytes role outerFuel)
    (statementTraceDecoder (globalOnlineNext ns)
      (fun _ key => targetOfRaw role (keyBytes key))
      (fun statement _ trace => roleLabelsFromBytes model ns role advice statement trace)
      innerFuel)
    (fun key => InRoleDomain role (keyBytes key))
    (fun _ label output => typedCompleteRawBad model routes role label output)
    authorized

/-- Actual all-salt two-pass instability with the actual capped samplers.
The only remaining model parameter is the current relation, not a desired
probability or successful-extraction premise. -/
theorem current_role_instability {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte)) (cap : Nat) :
    InstabilityBound
      (currentRoleEvent model ns keyBytes counter routes role advice
        outerFuel innerFuel authorized)
      cap ((6 * cap : Rat) / (2^512 : Rat) + completeRoleLoss role) := by
  simpa only [currentRoleEvent, currentOuter] using (rp05_role_instability ns keyBytes counter
    (fun key => targetOfRaw role (keyBytes key))
    (fun _ trace => preambleFromTrace ns role trace)
    (fun _ key => targetOfRaw role (keyBytes key))
    (fun statement _ trace => roleLabelsFromBytes model ns role advice statement trace)
    outerFuel innerFuel authorized cap
    (fun key => InRoleDomain role (keyBytes key))
    (fun _ label output => typedCompleteRawBad model routes role label output)
    (completeRoleLoss role) (complete_role_loss_nonnegative role)
    (fun _ label => typed_complete_raw_density model routes role label))

/-- Marking a statement only removes selected-role bad states. -/
theorem current_role_mark_mono {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (database : Database Key (VectorOutput Counter))
    (after : currentRoleEvent model ns keyBytes counter routes role advice
      outerFuel innerFuel (insert statement authorized) database) :
    currentRoleEvent model ns keyBytes counter routes role advice
      outerFuel innerFuel authorized database := by
  simpa [currentRoleEvent, currentOuter] using
    (role_event_mark_mono _ _ _ _ _ _ _ authorized statement database
      (by simpa [currentRoleEvent, currentOuter] using after))

/-- Literal v2 leaf programming cannot create a selected-role event.  No
caller-supplied domain-separation or event-invariance premise is needed. -/
theorem current_role_event_marked_write_iff {Key Counter : Type*}
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    (model : RelationModel) (ns : SmzaRp05LeafNamespace.Namespace)
    (keyBytes : Key → V8SmzaOracleParser.RawInput) (counter : Counter)
    (routes : TypedRoutes model Counter) (role : Role)
    (advice : AllEarlierTables model role) (outerFuel innerFuel : Nat)
    (authorized : Finset (List Byte)) (statement : List Byte)
    (marked : statement ∈ authorized) (key : Key)
    (parsed : globalLeafStatement ns (keyBytes key) = some statement)
    (left right : Database Key (VectorOutput Counter))
    (sameOutside : ∀ other, other ≠ key → left other = right other) :
    currentRoleEvent model ns keyBytes counter routes role advice
        outerFuel innerFuel authorized left ↔
      currentRoleEvent model ns keyBytes counter routes role advice
        outerFuel innerFuel authorized right := by
  simpa [currentRoleEvent, currentOuter] using
    (role_event_iff_off_marked_key _ _ _ _ _ _ _ authorized statement marked key
      (SmzaRp05ChallengeRecordErasure.global_leaf_statement_not_in_role_domain
        ns (keyBytes key) statement parsed role)
      parsed left right sameOutside)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentRoleLabels
