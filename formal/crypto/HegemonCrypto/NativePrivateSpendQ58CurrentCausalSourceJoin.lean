import HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics
import HegemonCrypto.NativePrivateSpendQ58CurrentCausalHistoryDensity

/-! Literal current constructor data and causal labels. The fixed CSR template
is the source-owned normalized native datum under the existing F1 boundary;
it has no stage, database, vector or adversary argument. Its ordered terms are
mapped by div/mod64, without sorting or removing duplicate terms. Only the
last77 targets vary with the canonical pub fields. These data equalities
contain no acceptance, Satisfies, failure inclusion or extraction assumption.
The final global selector transport remains a separate obligation. SOURCE ONLY.
-/
namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCausalSourceJoin
open scoped Classical
open SmzaRp05ExecutableMerkleVerifier (Program Oracle)
open SmzaChallengeStageTargets (Role)
namespace R
export NativePrivateSpendQ58CurrentPublicOpening
  (Row Lane Check Batch Values Relation Satisfies)
end R
namespace F
export NativePrivateSpendQ58CurrentFullStageEnvelope
  (Trace RawInput RawDigest Context Payload rawPayload Valid)
end F
namespace T
export NativePrivateSpendQ58CurrentTracePiopMass (child childDigest traceInput)
end T
namespace O
export NativePrivateSpendQ58CurrentFixedOpeningReplay
  (fixedOracle fixedOpening)
end O
namespace E
export NativePrivateSpendQ58CurrentExecutableVerifier
  (Opening openingScan canonicalOpening)
end E
namespace G
export NativePrivateSpendQ58CurrentConstructorGrouping
  (Counter Key keyBytes)
end G
namespace GF
export NativePrivateSpendQ58CurrentGammaFiber (currentRoleCaps)
end GF
namespace FM
export NativePrivateSpendQ58CurrentFiberMassTransport
  (FixedVectors actualFixed Active)
end FM
noncomputable section
set_option autoImplicit false
set_option Elab.async false
set_option maxHeartbeats 0
set_option maxRecDepth 0

abbrev AbsoluteTerm := Fin (26210 * 64) × Goldilocks
abbrev PackedTerm := (R.Row × R.Lane) × Goldilocks

/-- Immutable normalized source data, not a relation chosen after a stage.
The sole runtime variation is the separately parsed canonical public77. -/
structure SourceTemplate where
  rawTerms : R.Check → List AbsoluteTerm
  nonpublicTarget : R.Check → Goldilocks

def rowAddress (coordinate : R.Row × R.Lane) : Nat :=
  coordinate.1.val * 64 + coordinate.2.val

def encodedTerms (terms : List PackedTerm) : List (Nat × Goldilocks) :=
  terms.map fun term => (rowAddress term.1, term.2)

def nativeTerm (term : AbsoluteTerm) : PackedTerm :=
  ((⟨term.1.val / 64, by have bound := term.1.isLt; omega⟩,
    ⟨term.1.val % 64, Nat.mod_lt _ (by decide)⟩), term.2)

def nativeTerms (terms : List AbsoluteTerm) : List PackedTerm :=
  terms.map nativeTerm

theorem row_address_injective : Function.Injective rowAddress := by
  intro left right same
  rcases left with ⟨leftRow, leftLane⟩
  rcases right with ⟨rightRow, rightLane⟩
  have rowEq : leftRow = rightRow := Fin.ext (by
    simp only [rowAddress] at same
    have leftBound := leftLane.isLt
    have rightBound := rightLane.isLt
    omega)
  have laneEq : leftLane = rightLane := Fin.ext (by
    simp only [rowAddress] at same
    have leftBound := leftLane.isLt
    have rightBound := rightLane.isLt
    omega)
  exact Prod.ext rowEq laneEq

/-- Encoded CSR list equality determines the entire ordered packed list. -/
theorem encoded_terms_injective : Function.Injective encodedTerms := by
  intro left
  induction left with
  | nil =>
      intro right same
      cases right with
      | nil => rfl
      | cons head tail => simp [encodedTerms] at same
  | cons head tail ih =>
      intro right same
      cases right with
      | nil => simp [encodedTerms] at same
      | cons other rest =>
          change (rowAddress head.1, head.2) :: encodedTerms tail =
            (rowAddress other.1, other.2) :: encodedTerms rest at same
          have split := List.cons.inj same
          have coordinates := row_address_injective (congrArg Prod.fst split.1)
          have coefficient := congrArg Prod.snd split.1
          exact congrArg₂ List.cons (Prod.ext coordinates coefficient) (ih split.2)

theorem native_terms_exact (terms : List AbsoluteTerm) :
    encodedTerms (nativeTerms terms) = terms.map fun term => (term.1.val, term.2) := by
  induction terms with
  | nil => rfl
  | cons head tail ih =>
      change (rowAddress (nativeTerm head).1, (nativeTerm head).2) ::
        encodedTerms (nativeTerms tail) =
        (head.1.val, head.2) :: (tail.map fun term => (term.1.val, term.2))
      rw [ih]
      congr 1
      apply Prod.ext
      · change (head.1.val / 64) * 64 + head.1.val % 64 = head.1.val
        omega
      · rfl

/-- circuit.rs/htlc.rs literal current product occurrence-row constructor. -/
def nativeBatch (batch : R.Batch) (operand : Fin 3) : R.Row :=
  ⟨10580 + 3 * batch.val + operand.val, by
    have batchBound := batch.isLt
    have operandBound := operand.isLt
    omega⟩

def nativeTarget (template : SourceTemplate) (pub : Fin 77 → Goldilocks)
    (check : R.Check) : Goldilocks :=
  if before : check.val < 1344517 then template.nonpublicTarget check
  else pub ⟨check.val - 1344517, by have bound := check.isLt; omega⟩

def nativeRelation (template : SourceTemplate) (pub : Fin 77 → Goldilocks) : R.Relation :=
  { batch := nativeBatch
    csr := fun check => nativeTerms (template.rawTerms check)
    target := nativeTarget template pub }

/-- Ordinary original native row/getter data. This is the precise finite F1
constructor instantiation needed at the causal seam. None of its fields is an
acceptance, semantic validity, event support or security bound premise. -/
structure NativeDataReadback (template : SourceTemplate)
    (pub : Fin 77 → Goldilocks) (actual : R.Relation) : Prop where
  entries : ∀ check, encodedTerms (actual.csr check) =
    (template.rawTerms check).map fun term => (term.1.val, term.2)
  beforeTargets : ∀ check, check.val < 1344517 →
    actual.target check = template.nonpublicTarget check
  publicTargets : ∀ i : Fin 77,
    actual.target ⟨1344517 + i.val, by have bound := i.isLt; omega⟩ = pub i
  productRows : ∀ batch operand,
    (actual.batch batch operand).val = 10580 + 3 * batch.val + operand.val

theorem native_data_identifies_relation (template : SourceTemplate)
    (pub : Fin 77 → Goldilocks) (actual : R.Relation)
    (data : NativeDataReadback template pub actual) :
    actual = nativeRelation template pub := by
  have batchEq : actual.batch = nativeBatch := by
    funext batch operand
    exact Fin.ext (data.productRows batch operand)
  have csrEq : actual.csr = fun check => nativeTerms (template.rawTerms check) := by
    funext check
    exact encoded_terms_injective ((data.entries check).trans
      (native_terms_exact (template.rawTerms check)).symm)
  have targetEq : actual.target = nativeTarget template pub := by
    funext check
    by_cases before : check.val < 1344517
    · simpa only [nativeTarget, dif_pos before] using data.beforeTargets check before
    · let i : Fin 77 := ⟨check.val - 1344517, by have bound := check.isLt; omega⟩
      have selected : (⟨1344517 + i.val, by have bound := i.isLt; omega⟩ : R.Check) = check :=
        Fin.ext (by dsimp [i]; omega)
      have target := data.publicTargets i
      rw [selected] at target
      simpa only [nativeTarget, dif_neg before] using target
  cases actual
  cases batchEq
  cases csrEq
  cases targetEq
  rfl

/- The retained certificate's original finite CSR/layout data supplies
NativeDataReadback. The index identities are ordinary original loop addresses,
not a missing semantic or coverage assumption. All existing exhaustive
CertificateChecks/Covers fields remain in the retained certificate unchanged. -/
section RetainedCertificate
local instance sourcePrimeFact : Fact (Nat.Prime HegemonCrypto.NativePrivateSpendLocalSemantics.modulus) :=
  ⟨HegemonCrypto.SmallWood.goldilocks_prime⟩

structure CertificateNativeData (template : SourceTemplate) (pub : Fin 77 → Goldilocks)
    (actual : R.Relation) (graph : HegemonCrypto.NativePrivateSpendPackedLowering.Graph Goldilocks)
    (layout : HegemonCrypto.NativePrivateSpendPackedLowering.Layout Goldilocks)
    (csr : HegemonCrypto.NativePrivateSpendCsrCertificate.RawCSR Goldilocks)
    (certificate : HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics.RelationCertificate
      actual graph layout csr) : Prop where
  rowCount : csr.rowCount = 1344594
  batchCount : layout.batchCount = 5210
  canonicalRows : layout.canonicalRows = 10580
  checkIndex : ∀ i, (certificate.checkIndex i).val = i.val
  batchIndex : ∀ i, (certificate.batchIndex i).val = i.val
  entries : ∀ i, (HegemonCrypto.NativePrivateSpendCsrCertificate.rawRow csr i).entries =
    (template.rawTerms (certificate.checkIndex i)).map fun term => (term.1.val, term.2)
  targets : ∀ i, (HegemonCrypto.NativePrivateSpendCsrCertificate.rawRow csr i).target =
    nativeTarget template pub (certificate.checkIndex i)

theorem retained_certificate_supplies_native_data
    (template : SourceTemplate) (pub : Fin 77 → Goldilocks)
    (actual : R.Relation) (graph : HegemonCrypto.NativePrivateSpendPackedLowering.Graph Goldilocks)
    (layout : HegemonCrypto.NativePrivateSpendPackedLowering.Layout Goldilocks)
    (csr : HegemonCrypto.NativePrivateSpendCsrCertificate.RawCSR Goldilocks)
    (certificate : HegemonCrypto.NativePrivateSpendCurrentSixCaseSemantics.RelationCertificate
      actual graph layout csr)
    (data : CertificateNativeData template pub actual graph layout csr certificate) :
    NativeDataReadback template pub actual := by
  have rowFor (check : R.Check) :
      ∃ i : Fin csr.rowCount, certificate.checkIndex i = check := by
    let i : Fin csr.rowCount := ⟨check.val, by rw [data.rowCount]; exact check.isLt⟩
    exact ⟨i, Fin.ext (data.checkIndex i)⟩
  constructor
  · intro check
    obtain ⟨i, same⟩ := rowFor check
    have original := certificate.entries i
    change (HegemonCrypto.NativePrivateSpendCsrCertificate.rawRow csr i).entries =
      encodedTerms (actual.csr (certificate.checkIndex i)) at original
    exact (by rw [← same]; exact original.symm.trans (data.entries i))
  · intro check before
    obtain ⟨i, same⟩ := rowFor check
    have target := (certificate.targets i).symm.trans (data.targets i)
    rw [same] at target
    change (actual.target check : Goldilocks) = nativeTarget template pub check at target
    simpa only [nativeTarget, dif_pos before] using target
  · intro index
    let check : R.Check := ⟨1344517 + index.val, by have bound := index.isLt; omega⟩
    obtain ⟨i, same⟩ := rowFor check
    have target := (certificate.targets i).symm.trans (data.targets i)
    rw [same] at target
    change (actual.target check : Goldilocks) = nativeTarget template pub check at target
    have after : ¬ check.val < 1344517 := by dsimp [check]; omega
    have word : (⟨check.val - 1344517, by have bound := check.isLt; omega⟩ : Fin 77) = index :=
      Fin.ext (by dsimp [check]; omega)
    simpa only [nativeTarget, dif_neg after, word] using target
  · intro batch operand
    let i : Fin layout.batchCount := ⟨batch.val, by rw [data.batchCount]; exact batch.isLt⟩
    have same : certificate.batchIndex i = batch := Fin.ext (data.batchIndex i)
    have product := certificate.products i operand (0 : R.Lane)
    rw [same] at product
    change (layout.canonicalRows + 3*i.val + operand.val)*64 + 0 =
      (actual.batch batch operand).val*64 + 0 at product
    rw [data.canonicalRows] at product
    have index : i.val = batch.val := rfl
    rw [index] at product
    omega
end RetainedCertificate

/-- Same literal current root subtree, with current framing parsed before
extracting pub fields. Failure and missing traces retain total defaults. -/
def rootTrace (role : Role) (trace : F.Trace) : F.Trace :=
  match role with
  | .decsMatrix => trace
  | .piopMatrix => T.child trace 0
  | .piopOpening => T.child (T.child trace 0) 0
  | .decsSample => T.child (T.child (T.child trace 0) 0) 0

def causalBinding (role : Role) (trace : F.Trace) : List HegemonCrypto.CanonicalBytes.Byte :=
  match F.rawPayload (T.traceInput (rootTrace role trace)) with
  | none => []
  | some payload => if payload.kind = .root then payload.bytes.drop 96 else []

def causalPublic (role : Role) (trace : F.Trace) : Fin 77 → Goldilocks :=
  fun i => (V8SmzaOracleParser.wordAt (causalBinding role trace) i.val : Goldilocks)

def causalRelation (template : SourceTemplate) (role : Role) (trace : F.Trace) : R.Relation :=
  nativeRelation template (causalPublic role trace)

/-- The actual current parsed root constructor identifies all616 binding
bytes. No equality of namespace/profile IDs stands in for these bytes. -/
theorem recorded_root_identifies_causal_binding
    (role : Role) (trace : F.Trace) (context : F.Context) (payload : F.Payload)
    (parsed : F.rawPayload (T.traceInput (rootTrace role trace)) = some payload)
    (kind : payload.kind = .root) (valid : F.Valid context payload) :
    causalBinding role trace = context.binding := by
  have binding : payload.bytes.drop 96 = context.binding := by
    unfold F.Valid at valid
    rw [kind] at valid
    exact valid.2.2.2
  simp only [causalBinding, parsed, kind]
  exact binding

theorem recorded_root_identifies_causal_public
    (role : Role) (trace : F.Trace) (context : F.Context) (payload : F.Payload)
    (parsed : F.rawPayload (T.traceInput (rootTrace role trace)) = some payload)
    (kind : payload.kind = .root) (valid : F.Valid context payload) :
    causalPublic role trace =
      (fun i : Fin 77 => (V8SmzaOracleParser.wordAt context.binding i.val : Goldilocks)) := by
  exact congrArg
    (fun binding : List HegemonCrypto.CanonicalBytes.Byte =>
      fun i : Fin 77 => (V8SmzaOracleParser.wordAt binding i.val : Goldilocks))
    (recorded_root_identifies_causal_binding role trace context payload parsed kind valid)

/-- Every successful canonicalOpening used the same deterministic first
scan. The proof derives this from the actual Program bind and nonce check. -/
theorem canonical_opening_has_same_scan
    (pending : Bool) (nonce : Fin (2^32)) (digest : F.RawDigest)
    (oracle : Oracle) (opening : E.Opening) (finalPending : Bool)
    (executed : (E.canonicalOpening pending nonce digest).eval oracle =
      some (opening, finalPending)) :
    ∃ firstOpening scanPending,
      (E.openingScan digest (List.range 16) pending).eval oracle =
        some (nonce.val, firstOpening, scanPending) := by
  unfold E.canonicalOpening at executed
  obtain ⟨chosen, scanned, continued⟩ :=
    SmzaRp05FinalProgramMiddleExecution.program_bind_success oracle
      (E.openingScan digest (List.range 16) pending) _ (opening, finalPending) executed
  rcases chosen with ⟨expected, firstOpening, scanPending⟩
  by_cases equal : nonce.val = expected
  · exact ⟨firstOpening, scanPending, by simpa only [← equal] using scanned⟩
  · simp [equal, Program.eval] at continued

/-- Deterministic nonce label, including a harmless total default on failure.
It receives no accepted nonce, stage, active database or vector. -/
def scanNonce (pending : Bool) (oracle : Oracle) (digest : F.RawDigest) : Fin (2^32) :=
  match (E.openingScan digest (List.range 16) pending).eval oracle with
  | none => 0
  | some selected => if bounded : selected.1 < 2^32 then ⟨selected.1, bounded⟩ else 0

theorem canonical_opening_identifies_scan_nonce
    (pending : Bool) (nonce : Fin (2^32)) (digest : F.RawDigest)
    (oracle : Oracle) (opening : E.Opening) (finalPending : Bool)
    (executed : (E.canonicalOpening pending nonce digest).eval oracle =
      some (opening, finalPending)) :
    scanNonce pending oracle digest = nonce := by
  obtain ⟨firstOpening, scanPending, scanned⟩ :=
    canonical_opening_has_same_scan pending nonce digest oracle opening finalPending executed
  unfold scanNonce
  rw [scanned]
  dsimp only
  rw [dif_pos nonce.isLt]

/-- The DECS sample label uses exactly the current same fixed-other-role
oracle already used by fixedOpening. Other roles do not consume this nonce. -/
def causalNonce {Result : Type} (program : Program Result) (fallback : F.RawDigest) :
    (role : Role) → FM.FixedVectors (Counter := G.Counter) role (G.keyBytes program) →
      F.Trace → Fin (2^32)
  | .decsSample, fixed, trace =>
      scanNonce false
        (O.fixedOracle program .decsSample GF.currentRoleCaps
          (FM.actualFixed .decsSample (G.keyBytes program) fixed) fallback)
        (T.childDigest trace)
  | _, _, _ => 0

/-- Source-data equality and the canonical scan identify the two actual
constructor parameters without any after-the-fact relation/nonce callbacks. -/
theorem native_causal_data_identifies_relation
    (template : SourceTemplate) (role : Role) (trace : F.Trace)
    (context : F.Context) (payload : F.Payload) (actual : R.Relation)
    (parsed : F.rawPayload (T.traceInput (rootTrace role trace)) = some payload)
    (kind : payload.kind = .root) (valid : F.Valid context payload)
    (data : NativeDataReadback template
      (fun i : Fin 77 => (V8SmzaOracleParser.wordAt context.binding i.val : Goldilocks)) actual) :
    actual = causalRelation template role trace := by
  unfold causalRelation
  rw [recorded_root_identifies_causal_public role trace context payload parsed kind valid]
  exact native_data_identifies_relation template _ actual data

/-- All constructor parameters are computed from the fixed source template,
actual parsed causal trace and fixed other-role oracle; no callbacks remain. -/
def causalBad {Result : Type} (program : Program Result) (template : SourceTemplate)
    (fallback : F.RawDigest) (role : Role)
    (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes program)) :=
  NativePrivateSpendQ58CurrentCausalHistoryDensity.labelledBad program fallback role fixed
    (fun trace _ => causalRelation template role trace)
    (fun trace _ => causalNonce program fallback role fixed trace)

theorem current_native_causal_density {Result : Type} (program : Program Result)
    (template : SourceTemplate) (fallback : F.RawDigest) (role : Role)
    (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (injective : Function.Injective NativePrivateSpendQ58CurrentAcceptedLeafSupport.currentPoint)
    (sample : NativePrivateSpendQ58CurrentDecsSampleDensity.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point)
    (trace : F.Trace) (key : FM.Active role (G.keyBytes program)) :
    HegemonCrypto.CmsClassicalDatabase.outputEventProbability
      (causalBad program template fallback role fixed trace key) ≤
      NativePrivateSpendQ58CurrentRoleEventPhysicalMass.localLoss role := by
  exact NativePrivateSpendQ58CurrentCausalHistoryDensity.current_causal_label_density
    program fallback role fixed (fun trace _ => causalRelation template role trace)
    (fun trace _ => causalNonce program fallback role fixed trace)
    injective sample point lookup trace key

theorem current_native_causal_instability {Result : Type} (program : Program Result)
    (template : SourceTemplate) (fallback : F.RawDigest) (role : Role)
    (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (injective : Function.Injective NativePrivateSpendQ58CurrentAcceptedLeafSupport.currentPoint)
    (sample : NativePrivateSpendQ58CurrentDecsSampleDensity.Position) (point : Goldilocks)
    (lookup : SmzaRp05DecsPointProjection.fieldPoint 13173 sample.val = some point)
    (budget : Nat) :
    HegemonCrypto.CmsClassicalDatabase.InstabilityBound
      (SmzaDynamicDatabaseSoundness.DynamicBad
        (NativePrivateSpendQ58CurrentPrequeryEvents.currentLabel
          (NativePrivateSpendQ58CurrentFiberMassTransport.activeBytes role (G.keyBytes program))
          NativePrivateSpendQ58CurrentConstructorGrouping.zero
          (NativePrivateSpendQ58CurrentRoleEventPhysicalMass.stage role))
        (causalBad program template fallback role fixed)) budget
      ((3*budget : Rat)/(2^512 : Rat)+
        NativePrivateSpendQ58CurrentRoleEventPhysicalMass.localLoss role) := by
  exact NativePrivateSpendQ58CurrentCausalHistoryDensity.current_causal_label_instability
    program fallback role fixed (fun trace _ => causalRelation template role trace)
    (fun trace _ => causalNonce program fallback role fixed trace)
    injective sample point lookup budget

/-- The DECS source event's nonce is identified by the actual canonical
opening replay on exactly the same fixed-other-role oracle and trace digest. -/
theorem actual_fixed_opening_identifies_causal_nonce
    {Result : Type} (program : Program Result) (fallback : F.RawDigest)
    (fixed : FM.FixedVectors (Counter := G.Counter) .decsSample (G.keyBytes program))
    (trace : F.Trace) (nonce : Fin (2^32)) (opening : E.Opening) (pending : Bool)
    (executed : (E.canonicalOpening false nonce (T.childDigest trace)).eval
      (O.fixedOracle program .decsSample GF.currentRoleCaps
        (FM.actualFixed .decsSample (G.keyBytes program) fixed) fallback) =
        some (opening, pending)) :
    causalNonce program fallback .decsSample fixed trace = nonce := by
  exact canonical_opening_identifies_scan_nonce false nonce (T.childDigest trace)
    (O.fixedOracle program .decsSample GF.currentRoleCaps
      (FM.actualFixed .decsSample (G.keyBytes program) fixed) fallback)
    opening pending executed

/-- Literal current DECS matrix support does not depend on relation or nonce. -/
theorem current_decs_matrix_causal_support {Result : Type} (program : Program Result)
    (template : SourceTemplate) (fallback : F.RawDigest)
    (fixed : FM.FixedVectors (Counter := G.Counter) .decsMatrix (G.keyBytes program))
    (trace : F.Trace) (key : FM.Active .decsMatrix (G.keyBytes program))
    (vector : V8Smz9CoherentVectorMerkle.VectorOutput G.Counter)
    (actual : R.Relation) (nonce : Fin (2^32))
    (bad : NativePrivateSpendQ58CurrentRoleEventPhysicalMass.roleBad program actual fallback nonce
      .decsMatrix fixed trace key vector) :
    causalBad program template fallback .decsMatrix fixed trace key vector := by
  exact bad

attribute [local irreducible] NativePrivateSpendQ58CurrentDecsDynamicMass.fiberBad
  NativePrivateSpendQ58CurrentFiberMassTransport.matrixEvent
  NativePrivateSpendQ58CurrentFiberMassTransport.openingEvent

/-- Same physical DECS sample event, with the source-derived scan nonce. -/
theorem current_decs_sample_causal_support {Result : Type} (program : Program Result)
    (template : SourceTemplate) (fallback : F.RawDigest)
    (fixed : FM.FixedVectors (Counter := G.Counter) .decsSample (G.keyBytes program))
    (trace : F.Trace) (key : FM.Active .decsSample (G.keyBytes program))
    (vector : V8Smz9CoherentVectorMerkle.VectorOutput G.Counter)
    (actual : R.Relation) (nonce : Fin (2^32)) (opening : E.Opening) (pending : Bool)
    (executed : (E.canonicalOpening false nonce (T.childDigest trace)).eval
      (O.fixedOracle program .decsSample GF.currentRoleCaps
        (FM.actualFixed .decsSample (G.keyBytes program) fixed) fallback) =
        some (opening, pending))
    (bad : NativePrivateSpendQ58CurrentRoleEventPhysicalMass.roleBad program actual fallback nonce
      .decsSample fixed trace key vector) :
    causalBad program template fallback .decsSample fixed trace key vector := by
  have sameNonce := actual_fixed_opening_identifies_causal_nonce program fallback fixed trace
    nonce opening pending executed
  unfold causalBad NativePrivateSpendQ58CurrentCausalHistoryDensity.labelledBad
  dsimp only
  rw [sameNonce]
  exact bad

private theorem role_bad_relation_transport {Result : Type} (program : Program Result)
    (role : Role) (left right : R.Relation) (fallback : F.RawDigest) (nonce : Fin (2^32))
    (fixed : FM.FixedVectors (Counter := G.Counter) role (G.keyBytes program))
    (trace : F.Trace) (key : FM.Active role (G.keyBytes program))
    (vector : V8Smz9CoherentVectorMerkle.VectorOutput G.Counter)
    (equal : left = right)
    (bad : NativePrivateSpendQ58CurrentRoleEventPhysicalMass.roleBad program left fallback nonce
      role fixed trace key vector) :
    NativePrivateSpendQ58CurrentRoleEventPhysicalMass.roleBad program right fallback nonce
      role fixed trace key vector := by
  cases equal
  exact bad

/-- Current PIOP matrix support transports using only literal native data
and the actual recorded parsed root; no selected-stage inclusion is assumed. -/
theorem current_piop_matrix_causal_support {Result : Type} (program : Program Result)
    (template : SourceTemplate) (fallback : F.RawDigest)
    (fixed : FM.FixedVectors (Counter := G.Counter) .piopMatrix (G.keyBytes program))
    (trace : F.Trace) (key : FM.Active .piopMatrix (G.keyBytes program))
    (vector : V8Smz9CoherentVectorMerkle.VectorOutput G.Counter)
    (actual : R.Relation) (nonce : Fin (2^32)) (context : F.Context) (payload : F.Payload)
    (parsed : F.rawPayload (T.traceInput (rootTrace .piopMatrix trace)) = some payload)
    (kind : payload.kind = .root) (valid : F.Valid context payload)
    (data : NativeDataReadback template
      (fun i : Fin 77 => (V8SmzaOracleParser.wordAt context.binding i.val : Goldilocks)) actual)
    (bad : NativePrivateSpendQ58CurrentRoleEventPhysicalMass.roleBad program actual fallback nonce
      .piopMatrix fixed trace key vector) :
    causalBad program template fallback .piopMatrix fixed trace key vector := by
  have sameRelation := native_causal_data_identifies_relation template .piopMatrix trace context
    payload actual parsed kind valid data
  change NativePrivateSpendQ58CurrentRoleEventPhysicalMass.roleBad program
    (causalRelation template .piopMatrix trace) fallback nonce .piopMatrix fixed trace key vector
  with_reducible
    exact role_bad_relation_transport program .piopMatrix actual
      (causalRelation template .piopMatrix trace) fallback nonce fixed trace key vector
      sameRelation bad

theorem current_piop_opening_causal_support {Result : Type} (program : Program Result)
    (template : SourceTemplate) (fallback : F.RawDigest)
    (fixed : FM.FixedVectors (Counter := G.Counter) .piopOpening (G.keyBytes program))
    (trace : F.Trace) (key : FM.Active .piopOpening (G.keyBytes program))
    (vector : V8Smz9CoherentVectorMerkle.VectorOutput G.Counter)
    (actual : R.Relation) (nonce : Fin (2^32)) (context : F.Context) (payload : F.Payload)
    (parsed : F.rawPayload (T.traceInput (rootTrace .piopOpening trace)) = some payload)
    (kind : payload.kind = .root) (valid : F.Valid context payload)
    (data : NativeDataReadback template
      (fun i : Fin 77 => (V8SmzaOracleParser.wordAt context.binding i.val : Goldilocks)) actual)
    (bad : NativePrivateSpendQ58CurrentRoleEventPhysicalMass.roleBad program actual fallback nonce
      .piopOpening fixed trace key vector) :
    causalBad program template fallback .piopOpening fixed trace key vector := by
  have sameRelation := native_causal_data_identifies_relation template .piopOpening trace context
    payload actual parsed kind valid data
  change NativePrivateSpendQ58CurrentRoleEventPhysicalMass.roleBad program
    (causalRelation template .piopOpening trace) fallback nonce .piopOpening fixed trace key vector
  with_reducible
    exact role_bad_relation_transport program .piopOpening actual
      (causalRelation template .piopOpening trace) fallback nonce fixed trace key vector
      sameRelation bad

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58CurrentCausalSourceJoin
