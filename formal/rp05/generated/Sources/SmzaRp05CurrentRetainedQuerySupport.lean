import SmzaRp05CurrentRetainedResponseBridge
import SmzaRp05CurrentAcceptedQuerySupport
import SmzaRp05AcceptedMca406
import SmzaRp05GlobalOpeningReadback
import SmzaRp05CurrentMaxAgreementRecovery
import SmzaRp05CurrentTwelveCalculated
import SmzaRp05CurrentNativeSupportBridge

/-! # Same-stage q38 support from a retained response input

This composes the source-derived same-stage MCA/readback result with the
retained-input decoder. It removes the caller-provided `responseAtSample`
equation from current query-support conversion. The data and mask tables, and
their fixed-role leaf bindings, remain explicit inputs: this theorem does not
construct pre-gamma tables from post-query leaves or assert their chronology.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05CurrentRetainedQuerySupport

open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.SmallWood (Goldilocks)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05CurrentMaxAgreementRecovery (Position Query Coefficients ResponseRule)
open SmzaRp05GlobalOpeningReadback (GlobalQueryReadback)
open SmzaRp05GlobalOpeningReadback
  (decoded_oracle_agrees_with_global_root decodedOracle)
open SmzaRp05FilteredDecoderInstability (RawRecords globalOnlineNext)
open SmzaRp05DecsResponseProjection (decodeFieldRow)
open SmzaRp05CurrentAcceptedQuerySupport (sampledCoefficients
  accepted_query_subset_fixed_response_support)
open SmzaRp05ExecutablePcsClosureMca406 (NativeFiveMcaChecks406)
open SmzaRp05ExecutableMerkleVerifier (Log)
open SmzaRp05CurrentTwelveCalculated (CurrentTwelveAuthenticatedChecks)
open V8Smz9McaDecoder (responseSupport)
open V8SmzaOracleParser (RawDigest)
open V8Smz9OracleExtraction (wordToGoldilocks)
open V8Smz9CoherentMerkleGeometry (extract)
open SmzaRp05LeafNamespace (Namespace)
open SmzaRp05TracePrefixes (rootOracle fieldWordAt)
open SmzaRecordedTracePath (RecordsCollisionFree)

set_option autoImplicit false
set_option maxRecDepth 10000
noncomputable section

set_option allowUnsafeReducibility true in
attribute [local irreducible]
  SmzaRp05ExecutablePcsClosureStages.PcsStages.rows
attribute [local irreducible]
  HegemonCrypto.SmallWood.V8Smz9McaRecovery.querySampleFintype

private theorem decoded_toWord (values : List Goldilocks) :
    decodeFieldRow (values.map SmzaRp05ExecutableRestore.toWord) = values := by
  induction values with
  | nil => rfl
  | cons value rest _ih =>
      simp only [decodeFieldRow, List.map_cons]
      congr 1
      · simp [SmzaRp05ExecutableRestore.toWord]

private theorem map_getD_default {α β : Type} (values : List α) (f : α → β)
    (index : Nat) (fallback : α) :
    (values.map f).getD index (f fallback) = f (values.getD index fallback) := by
  induction values generalizing index with
  | nil => cases index <;> rfl
  | cons head tail ih => cases index <;> simp

/-- The fixed data table read from a frozen, role-erased raw-record set.
Values outside the 140 data columns default to zero, matching the total table
type consumed by the finite recovery experiment. -/
def measuredDataTable (ns : Namespace) (records : RawRecords) (fuel : Nat)
    (root : RawDigest) : Nat → Position → Goldilocks :=
  fun column position => if within : column < 140 then
    wordToGoldilocks
      (rootOracle ns (extract (globalOnlineNext ns) records fuel .root root)
        position ⟨column, by change column < 145; omega⟩)
  else 0

/-- The fixed five-row mask table extracted from the same frozen record set
as `measuredDataTable`. -/
def measuredMaskTable (ns : Namespace) (records : RawRecords) (fuel : Nat)
    (root : RawDigest) : Fin 5 → Position → Goldilocks :=
  fun row position => wordToGoldilocks
    (rootOracle ns (extract (globalOnlineNext ns) records fuel .root root)
      position ⟨140 + row.val, by change 140 + row.val < 145; omega⟩)

/-- The same global root extractor that defines the fixed role table reads
each authenticated query leaf back to its exact data and mask words. Thus
the leaf/table equations follow from the frozen record relation and its
collision-free branch, without choosing tables from the post-query leaves. -/
theorem measured_tables_match_global_query
    {ns : Namespace} {records : RawRecords} {root : RawDigest} {query : Query}
    (claims : GlobalQueryReadback ns records root query)
    (collisionFree : RecordsCollisionFree records) (fuel : Nat)
    (enough : 25 ≤ fuel) (coordinates : Fin 38 → Position)
    (queryImage : query.val = Finset.univ.image coordinates) :
    (∀ j : Fin 38, ∀ column : Fin 140,
      measuredDataTable ns records fuel root column.val (coordinates j) =
        wordToGoldilocks
          (SmzaRp05TracePrefixes.fieldWordAt
            (claims.leaf (coordinates j)).bytes (14 + column.val))) ∧
    (∀ j : Fin 38, ∀ row : Fin 5,
      measuredMaskTable ns records fuel root row (coordinates j) =
        wordToGoldilocks
          (SmzaRp05TracePrefixes.fieldWordAt
            (claims.leaf (coordinates j)).bytes (155 + row.val))) := by
  constructor
  · intro j column
    have member : coordinates j ∈ query.val := by
      rw [queryImage]
      exact Finset.mem_image.mpr ⟨j, Finset.mem_univ _, rfl⟩
    have read := decoded_oracle_agrees_with_global_root claims collisionFree
      fuel enough (coordinates j) member
        ⟨column.val, by omega⟩
    change rootOracle ns (extract (globalOnlineNext ns) records fuel .root root)
        (coordinates j) ⟨column.val, by change column.val < 145; omega⟩ =
      SmzaRp05TracePrefixes.fieldWordAt (claims.leaf (coordinates j)).bytes
        (if column.val < 140 then 14 + column.val
          else 155 + (column.val - 140)) at read
    rw [if_pos column.isLt] at read
    unfold measuredDataTable
    rw [dif_pos column.isLt]
    exact congrArg wordToGoldilocks read
  · intro j row
    have member : coordinates j ∈ query.val := by
      rw [queryImage]
      exact Finset.mem_image.mpr ⟨j, Finset.mem_univ _, rfl⟩
    have read := decoded_oracle_agrees_with_global_root claims collisionFree
      fuel enough (coordinates j) member
        ⟨140 + row.val, by omega⟩
    change rootOracle ns (extract (globalOnlineNext ns) records fuel .root root)
        (coordinates j) ⟨140 + row.val,
          by change 140 + row.val < 145; omega⟩ =
      SmzaRp05TracePrefixes.fieldWordAt (claims.leaf (coordinates j)).bytes
        (if 140 + row.val < 140 then 14 + (140 + row.val)
          else 155 + ((140 + row.val) - 140)) at read
    rw [if_neg (by omega : ¬ 140 + row.val < 140)] at read
    change wordToGoldilocks
        (rootOracle ns (extract (globalOnlineNext ns) records fuel .root root)
          (coordinates j) ⟨140 + row.val,
            by change 140 + row.val < 145; omega⟩) = _
    rw [show 140 + row.val - 140 = row.val by omega] at read
    exact congrArg wordToGoldilocks read

/-- Convenient committed-oracle form of the same fixed-table readback.  The
terminal table and the query's decoded oracle agree at every selected data
column and mask row, with both sides tied to the exact same `claims`. -/
theorem measured_tables_match_decoded_oracle
    {ns : Namespace} {records : RawRecords} {root : RawDigest} {query : Query}
    (claims : GlobalQueryReadback ns records root query)
    (collisionFree : RecordsCollisionFree records) (fuel : Nat)
    (enough : 25 ≤ fuel) (coordinates : Fin 38 → Position)
    (queryImage : query.val = Finset.univ.image coordinates) :
    (∀ j : Fin 38, ∀ column : Fin 140,
      measuredDataTable ns records fuel root column.val (coordinates j) =
        wordToGoldilocks
          (SmzaRp05GlobalOpeningReadback.decodedOracle claims (coordinates j)
            ⟨column.val, by change column.val < 145; omega⟩)) ∧
    (∀ j : Fin 38, ∀ row : Fin 5,
      measuredMaskTable ns records fuel root row (coordinates j) =
        wordToGoldilocks
          (SmzaRp05GlobalOpeningReadback.decodedOracle claims (coordinates j)
            ⟨140 + row.val, by change 140 + row.val < 145; omega⟩)) := by
  have fields := measured_tables_match_global_query claims collisionFree fuel enough
    coordinates queryImage
  constructor
  · intro j column
    have decoded := fields.1 j column
    have oracleEq :
        SmzaRp05GlobalOpeningReadback.decodedOracle claims (coordinates j)
          ⟨column.val, by change column.val < 145; omega⟩ =
        SmzaRp05TracePrefixes.fieldWordAt (claims.leaf (coordinates j)).bytes
          (14 + column.val) := by
      simp [SmzaRp05GlobalOpeningReadback.decodedOracle, column.isLt]
    rw [oracleEq]
    exact decoded
  · intro j row
    have decoded := fields.2 j row
    have oracleEq :
        SmzaRp05GlobalOpeningReadback.decodedOracle claims (coordinates j)
          ⟨140 + row.val, by change 140 + row.val < 145; omega⟩ =
        SmzaRp05TracePrefixes.fieldWordAt (claims.leaf (coordinates j)).bytes
          (155 + row.val) := by
      simp only [SmzaRp05GlobalOpeningReadback.decodedOracle,
        if_neg (by omega : ¬ 140 + row.val < 140),
        show 140 + row.val - 140 = row.val from by omega]
    rw [oracleEq]
    exact decoded

set_option maxHeartbeats 1000000 in
/-- From the actual successful PCS stage, derive the restored rows, native
five-MCA checks, same-run q38 leaf readback, and the fixed-response support
inclusion. The only remaining table obligations are the data/mask role
bindings, supplied as a function over the exact authenticated leaves. The
pre-query record set is kept explicit so its physical CMS interpretation and
freshness/guess charge can be handled by the event-level join. -/
theorem same_stage_retained_input_query_support
    {ns : SmzaRp05LeafNamespace.Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List Goldilocks} {salt binding : List Byte}
    {statementBinding : List Nat} {tapes : List (List Byte)}
    {paths : List (List RawDigest)} {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6) (clean : finalPending = false)
    (priorRecords : SmzaRp05ExecutableMerkleVerifier.Log)
    (hasPriorInput : ∃ input, (input, hashFpp) ∈ priorRecords)
    (collisionFree : SmzaRecordedTracePath.RecordsCollisionFree
      ((priorRecords ++ (stages.hashProgram.record oracle).2).toFinset))
    (measured : RawRecords)
    (retained : ∀ stage raw digest,
      (raw, digest) ∈
        (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle stages.merkleInput).2 →
      (globalOnlineNext ns stage raw).isSome → (raw, digest) ∈ measured)
    (statementBindingLength : statementBinding.length = 138) :
    ∃ coordinates : Fin 38 → Position,
      ∃ query : Query,
        ∃ claims : GlobalQueryReadback ns measured stages.post.root query,
          ∃ polynomials : List SmzaRp05DecsResponseProjection.FieldRow,
            ∃ input,
              StrictMono coordinates ∧
              query.val = Finset.univ.image coordinates ∧
              (∀ j : Fin 38, (coordinates j).val = stages.indexes.getD j.val 0) ∧
              (input, hashFpp) ∈ priorRecords ∧
              SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
                (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
                (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368 =
                  some polynomials ∧
              CurrentTwelveAuthenticatedChecks claims coordinates stages.heads
                (SmzaRp05CurrentTwelveCalculated.currentStageTails wire)
                (fun opening => points.getD opening.val 0) ∧
              ∀ (data : Nat → Position → Goldilocks)
                (masks : Fin 5 → Position → Goldilocks),
                (∀ j : Fin 38, ∀ column : Fin 140,
                  data column.val (coordinates j) =
                    V8Smz9OracleExtraction.wordToGoldilocks
                      (SmzaRp05TracePrefixes.fieldWordAt
                        (claims.leaf (coordinates j)).bytes (14 + column.val))) →
                (∀ j : Fin 38, ∀ row : Fin 5,
                  masks row (coordinates j) =
                    V8Smz9OracleExtraction.wordToGoldilocks
                      (SmzaRp05TracePrefixes.fieldWordAt
                        (claims.leaf (coordinates j)).bytes (155 + row.val))) →
                query.val ⊆ responseSupport
                  SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405 data masks
                  (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
                    (fun _ : Coefficients => input))
                  (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)) := by
  obtain ⟨coordinates, query, claims, polynomials, restore, coordinateIndex,
      ordered, image, leafBytes, pointBinding, _rowLengths, native⟩ :=
    SmzaRp05AcceptedMca406.accepted_pcs_stages_have_native_mca406_readback
      ns pending hPiop wire decs points salt binding statementBinding tapes paths
      oracle hashFpp finalPending stages clean measured retained
  obtain ⟨input, inputPolynomials, inputMember, restoreInput, responseReadback⟩ :=
    SmzaRp05CurrentRetainedResponseBridge.retained_record_set_has_fixed_response_readback
      stages priorRecords hasPriorInput collisionFree
      (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows stages.post))
      statementBindingLength
  have sameRows : polynomials = inputPolynomials :=
    Option.some.inj (restore.symm.trans restoreInput)
  have responseReadbackSame : ∀ row : Fin 5,
      HegemonCrypto.SmallWood.V8Smz9McaRecovery.responsePolynomials
        (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
          (fun _ : Coefficients => input)
          (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows stages.post))) row =
        SmzaRp05ExecutablePcsClosureAlgebra.coefficientPolynomial
          (polynomials.getD row.val []) := by
    intro row
    rw [sameRows]
    exact responseReadback row
  have responseAtSample := responseReadbackSame
  have currentChecks :=
    SmzaRp05CurrentTwelveCalculated.pcs_stages_authenticated_checks_on_readback
      stages pointCount claims coordinates pointBinding leafBytes
  refine ⟨coordinates, query, claims, polynomials, input, ordered, image,
    coordinateIndex, inputMember, restore, currentChecks, ?_⟩
  intro data masks dataBinding maskBinding
  have decodedPoints : ∀ j : Fin 38,
      (decodeFieldRow
        (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)).getD j.val 0 =
        SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint (coordinates j) := by
    intro j
    rw [decoded_toWord]
    exact pointBinding j
  have decodedRows : ∀ j : Fin 38,
      decodeFieldRow
        ((stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord).getD
          j.val []) = stages.rows.getD j.val [] := by
    intro j
    have mappedGet :
        ((stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord).getD
          j.val []) =
        (stages.rows.getD j.val []).map SmzaRp05ExecutableRestore.toWord := by
      simpa using map_getD_default stages.rows
        (fun row => row.map SmzaRp05ExecutableRestore.toWord) j.val []
    rw [mappedGet]
    exact decoded_toWord _
  have supportLeafBytes : ∀ j : Fin 38,
      (claims.leaf (coordinates j)).bytes =
        SmzaRp05PcsMerklePayload.normalizedLeafPayload salt (tapes.getD j.val [])
          (stages.indexes.getD j.val 0)
          (decodeFieldRow
            ((stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord).getD
              j.val [])) (decs.maskingEvals.getD j.val []) := by
    intro j
    rw [decodedRows j]
    exact leafBytes j
  have nativeSupportFn0 :=
    @SmzaRp05CurrentNativeSupportBridge.support_of_native_checks
      ns measured stages.post.root query claims coordinates image decs
      (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
      salt tapes stages.indexes
  have nativeSupportFn1 := nativeSupportFn0 coordinateIndex
  have nativeSupportFn2 := nativeSupportFn1 supportLeafBytes
  have nativeSupportFn3 := nativeSupportFn2 data masks
  have nativeSupportFn4 := nativeSupportFn3
    (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
      (fun _ : Coefficients => input))
    (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
    (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) polynomials
  have nativeSupportFn5 := nativeSupportFn4 restore
  have nativeSupportFn6 := nativeSupportFn5 native
  have nativeSupportFn7 := nativeSupportFn6 decodedPoints
  have nativeSupportFn8 := nativeSupportFn7 dataBinding
  have nativeSupportFn9 := nativeSupportFn8 maskBinding
  exact nativeSupportFn9 responseAtSample

/-- Actual-stage fixed-response support using the data/mask tables decoded
from the same frozen raw-record relation that authenticates the selected
leaves. This is a deterministic support inclusion only: the supplied record
sets do not, by themselves, establish that a response input was fixed before
q38 or that it has any independent-query density bound. -/
theorem same_stage_measured_root_query_support
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List Goldilocks} {salt binding : List Byte}
    {statementBinding : List Nat} {tapes : List (List Byte)}
    {paths : List (List RawDigest)} {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6) (clean : finalPending = false)
    (priorRecords : Log)
    (hasPriorInput : ∃ input, (input, hashFpp) ∈ priorRecords)
    (responseCollisionFree : RecordsCollisionFree
      ((priorRecords ++ (stages.hashProgram.record oracle).2).toFinset))
    (measured : RawRecords)
    (retained : ∀ stage raw digest,
      (raw, digest) ∈
        (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle stages.merkleInput).2 →
      (globalOnlineNext ns stage raw).isSome → (raw, digest) ∈ measured)
    (measuredCollisionFree : RecordsCollisionFree measured)
    (tableFuel : Nat) (tableFuelEnough : 25 ≤ tableFuel)
    (statementBindingLength : statementBinding.length = 138) :
    ∃ coordinates : Fin 38 → Position,
      ∃ query : Query,
        ∃ claims : GlobalQueryReadback ns measured stages.post.root query,
          ∃ polynomials : List SmzaRp05DecsResponseProjection.FieldRow,
            ∃ input,
              StrictMono coordinates ∧
              query.val = Finset.univ.image coordinates ∧
              (∀ j : Fin 38, (coordinates j).val = stages.indexes.getD j.val 0) ∧
              (input, hashFpp) ∈ priorRecords ∧
              SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
                (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
                (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368 =
                  some polynomials ∧
              CurrentTwelveAuthenticatedChecks claims coordinates stages.heads
                (SmzaRp05CurrentTwelveCalculated.currentStageTails wire)
                (fun opening => points.getD opening.val 0) ∧
              query.val ⊆ responseSupport
                SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405
                (measuredDataTable ns measured tableFuel stages.post.root)
                (measuredMaskTable ns measured tableFuel stages.post.root)
                (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
                  (fun _ : Coefficients => input))
                (sampledCoefficients (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)) := by
  obtain ⟨coordinates, query, claims, polynomials, input, ordered, image,
      coordinateIndex, inputMember, restore, currentChecks, support⟩ :=
    same_stage_retained_input_query_support
    stages pointCount clean priorRecords hasPriorInput responseCollisionFree
    measured retained statementBindingLength
  have tableBinding := measured_tables_match_global_query claims measuredCollisionFree
    tableFuel tableFuelEnough coordinates image
  exact ⟨coordinates, query, claims, polynomials, input, ordered, image,
    coordinateIndex, inputMember, restore, currentChecks,
    support (measuredDataTable ns measured tableFuel stages.post.root)
      (measuredMaskTable ns measured tableFuel stages.post.root)
      tableBinding.1 tableBinding.2⟩

/-- Deterministic terminal-record endpoint for one concrete PCS run.  The
record relation is made from that run's actual Merkle attempt and its actual
post-q38 hashFpp call; the same set supplies both authenticated query readback
and the global-root data/mask tables.  Its own hashFpp input is therefore
available for serialization consistency without an arbitrary retained-prefix
or caller-chosen table premise.

This is intentionally only a deterministic event inclusion (or a recorded
collision).  Since the response hash call occurs after q38, this theorem does
not give the response family a pre-query uniform-density law and must not be
used as a finite independent-query probability bound.  Adaptive probability
accounting belongs to the selected-role CMS instability/erasure argument. -/
theorem terminal_stage_query_support_or_collision
    {ns : Namespace} {pending : Bool} {hPiop : RawDigest}
    {wire : SmzaRp05PcsWireProjection.DecodedMiddleWire}
    {decs : SmzaRp05DecsResponseProjection.DecodedDecsResponseFields}
    {points : List Goldilocks} {salt binding : List Byte}
    {statementBinding : List Nat} {tapes : List (List Byte)}
    {paths : List (List RawDigest)}
    {oracle : SmzaRp05ExecutableMerkleVerifier.Oracle}
    {hashFpp : RawDigest} {finalPending : Bool}
    (stages : PcsStages ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending)
    (pointCount : points.length = 6) (clean : finalPending = false)
    (terminalFuel : Nat) (terminalFuelEnough : 25 ≤ terminalFuel)
    (statementBindingLength : statementBinding.length = 138) :
    (¬ RecordsCollisionFree
      (((SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle stages.merkleInput).2 ++
        (stages.hashProgram.record oracle).2).toFinset)) ∨
    ∃ coordinates : Fin 38 → Position,
      ∃ query : Query,
        ∃ claims : GlobalQueryReadback ns
          (((SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle
              stages.merkleInput).2 ++ (stages.hashProgram.record oracle).2).toFinset)
          stages.post.root query,
          ∃ polynomials : List SmzaRp05DecsResponseProjection.FieldRow,
            ∃ input,
              StrictMono coordinates ∧
              query.val = Finset.univ.image coordinates ∧
              (∀ j : Fin 38, (coordinates j).val = stages.indexes.getD j.val 0) ∧
              (input, hashFpp) ∈
                (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle
                  stages.merkleInput).2 ++ (stages.hashProgram.record oracle).2 ∧
              SmzaRp05DecsResponseProjection.restoredResponsePolynomials decs
                (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
                (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
                (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368 =
                  some polynomials ∧
              CurrentTwelveAuthenticatedChecks claims coordinates stages.heads
                (SmzaRp05CurrentTwelveCalculated.currentStageTails wire)
                (fun opening => points.getD opening.val 0) ∧
              query.val ⊆ responseSupport
                SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint 405
                (measuredDataTable ns
                  (((SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle
                    stages.merkleInput).2 ++ (stages.hashProgram.record oracle).2).toFinset)
                  terminalFuel stages.post.root)
                (measuredMaskTable ns
                  (((SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle
                    stages.merkleInput).2 ++ (stages.hashProgram.record oracle).2).toFinset)
                  terminalFuel stages.post.root)
                (SmzaRp05CurrentResponseInputDecoder.responseRuleOfRawInputSelection
                  (fun _ : Coefficients => input))
                (sampledCoefficients
                  (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)) := by
  classical
  let merkleLog :=
    (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle stages.merkleInput).2
  let hashLog := (stages.hashProgram.record oracle).2
  let allLog : Log := merkleLog ++ hashLog
  let allRecords : RawRecords := allLog.toFinset
  by_cases collisionFree : RecordsCollisionFree allRecords
  · have selectedInput :=
      SmzaRp05CurrentAcceptedRoleSupport.selected_response_hash_program_input
        stages.post.root decs
        (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
        (SmzaRp05PcsHashFppMiddle.gammaRows stages.post)
        (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
        140 368 statementBinding stages.hashProgram stages.responseBuilt
    obtain ⟨_, input, _, _, programEq⟩ := selectedInput
    have oracleEq : oracle input = hashFpp := by
      have executed := stages.hashExecuted
      rw [programEq,
        SmzaRp05ExecutableMerkleVerifier.Program.eval.eq_def] at executed
      exact Option.some.inj executed
    have inputCall : (input, hashFpp) ∈ hashLog := by
      change (input, hashFpp) ∈ (stages.hashProgram.record oracle).2
      simp [programEq, SmzaRp05ExecutableMerkleVerifier.Program.record,
        SmzaRp05ExecutableMerkleVerifier.ask, oracleEq]
    have hasInput : ∃ input, (input, hashFpp) ∈ allLog :=
      ⟨input, by simp [allLog, hashLog, inputCall]⟩
    have expandedSubset :
        ((allLog ++ hashLog).toFinset : RawRecords) ⊆ allRecords := by
      intro call member
      apply List.mem_toFinset.mpr
      have memberList := List.mem_toFinset.mp member
      rcases List.mem_append.mp memberList with fromAll | fromHash
      · change call ∈ merkleLog ++ hashLog at fromAll
        exact fromAll
      · change call ∈ merkleLog ++ hashLog
        exact List.mem_append.mpr (Or.inr fromHash)
    have responseCollisionFree : RecordsCollisionFree
        ((allLog ++ hashLog).toFinset) := by
      intro a b digest memberA memberB
      exact collisionFree a b digest (expandedSubset memberA) (expandedSubset memberB)
    have retained : ∀ stage raw digest,
        (raw, digest) ∈ merkleLog →
        (globalOnlineNext ns stage raw).isSome → (raw, digest) ∈ allRecords := by
      intro stage raw digest member _valid
      apply List.mem_toFinset.mpr
      simp [allLog, member]
    have support := same_stage_measured_root_query_support stages pointCount clean
      allLog hasInput responseCollisionFree allRecords retained collisionFree
      terminalFuel terminalFuelEnough statementBindingLength
    rcases support with ⟨coordinates, query, claims, polynomials, input,
        ordered, image, coordinateIndex, inputMember, restored, currentChecks, included⟩
    refine Or.inr ⟨coordinates, query, claims, polynomials, input, ordered, image,
      coordinateIndex, ?_, restored, currentChecks, included⟩
    simpa [allLog, merkleLog, hashLog] using inputMember
  · exact Or.inl (by simpa [allRecords, allLog, merkleLog, hashLog] using collisionFree)

end
end HegemonCrypto.SmallWood.SmzaRp05CurrentRetainedQuerySupport
