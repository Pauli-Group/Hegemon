import SmzaRp05GlobalOpeningReadback

/-!
# RP05 raw-log path validation

This checks decoded same-invocation SHA-512 query pairs and parser edges.  It
does not assert that the Rust verifier emitted the log, that a query output is
SHA-512 of its input, or that Rust acceptance implies this check succeeds.
Those are separate source-refinement obligations.  In particular, this is a
validated-evidence bridge, not an alternate definition of verifier acceptance.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05VerifierRunReadback

open V8Smz9CoherentMerkleGeometry SmzaRecordedTracePath
open SmzaRp05FilteredDecoderInstability SmzaRp05GlobalOpeningReadback
open SmzaRp05TracePrefixes
open SmzaRp05LeafNamespace SmzaRp05FilteredReadback
open SmzaQ38McaSourceBinding SmzaQ38OracleExtraction SmzaQ38LvcsOpening
open V8Smz9McaRecovery

set_option autoImplicit false

abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev Stage := V8SmzaOracleParser.Stage
abbrev RawRecords := V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest

/-- A raw query log is kept as a list, including repeated calls.  The finite
relation used by the recorded-path extractor forgets order and repeats, but
never invents an input/output pair absent from the log. -/
def logRecords (log : List (RawInput × RawDigest)) : RawRecords := log.toFinset

theorem mem_logRecords_iff (log : List (RawInput × RawDigest))
    (input : RawInput) (digest : RawDigest) :
    (input, digest) ∈ logRecords log ↔ (input, digest) ∈ log := by
  simp [logRecords]

/-- The supplied `inputs` are candidate raw preimages along one opened path.
Every step checks membership in the recorded query log, invokes the current
RP05 parser, and checks the indexed child digest and stage.  The terminal
case requires exactly one remaining input and a parseable final frame. -/
def validatePath (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (records : RawRecords) :
    Stage → RawDigest → List Nat → List RawInput → Option RawInput
  | stage, target, [], [input] =>
      if (input, target) ∈ records then
        if (next stage input).isSome then some input else none
      else none
  | stage, target, index :: rest, input :: inputs =>
      if (input, target) ∈ records then
        match next stage input with
        | none => none
        | some edges =>
            match edges[index]? with
            | none => none
            | some (childStage, childTarget) =>
                validatePath next records childStage childTarget rest inputs
      else none
  | _, _, _, _ => none

/-- A successful byte/edge check constructs, rather than assumes, the exact
inductive path consumed by the RP05 canonical leaf readback. -/
theorem validatePath_sound
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (records : RawRecords) (stage : Stage) (target : RawDigest)
    (path : List Nat) (inputs : List RawInput) (leaf : RawInput)
    (checked : validatePath next records stage target path inputs = some leaf) :
    RecordedPath next records stage target path leaf := by
  induction path generalizing stage target inputs with
  | nil =>
      cases inputs with
      | nil => simp [validatePath] at checked
      | cons input remaining =>
          cases remaining with
          | nil =>
              by_cases recorded : (input, target) ∈ records
              · by_cases valid : (next stage input).isSome
                · have same : input = leaf := Option.some.inj (by
                    simpa [validatePath, recorded, valid] using checked)
                  subst leaf
                  exact RecordedPath.here stage target input recorded valid
                · simp [validatePath, recorded, valid] at checked
              · simp [validatePath, recorded] at checked
          | cons other tail => simp [validatePath] at checked
  | cons index rest ih =>
      cases inputs with
      | nil => simp [validatePath] at checked
      | cons input remaining =>
          by_cases recorded : (input, target) ∈ records
          · cases parsed : next stage input with
            | none => simp [validatePath, recorded, parsed] at checked
            | some edges =>
                cases edge : edges[index]? with
                | none => simp [validatePath, recorded, parsed, edge] at checked
                | some child =>
                    rcases child with ⟨childStage, childTarget⟩
                    have belowChecked :
                        validatePath next records childStage childTarget rest remaining =
                          some leaf := by
                      simpa [validatePath, recorded, parsed, edge] using checked
                    exact RecordedPath.step stage target input edges index
                      childStage childTarget rest leaf recorded parsed edge
                      (ih childStage childTarget remaining belowChecked)
          · simp [validatePath, recorded] at checked

/-- The current query indices are checked against the exact decoded raw log.
The caller supplies only candidate preimages, not path propositions. -/
noncomputable def validateOpenedPaths (ns : Namespace)
    (log : List (RawInput × RawDigest)) (root : RawDigest) (query : Query)
    (inputs : Position → List RawInput)
    (expectedLeaf : Position → RawInput) : Bool :=
  query.val.toList.all fun index => decide
    (validatePath (globalOnlineNext ns) (logRecords log) .root root
      (0 :: SmzaRp05GlobalOpeningReadback.indexPath index 23)
      (inputs index) = some (expectedLeaf index))

theorem recorded_paths_of_validated_log
    (ns : Namespace) (log : List (RawInput × RawDigest))
    (root : RawDigest) (query : Query) (inputs : Position → List RawInput)
    (expectedLeaf : Position → RawInput)
    (checked : validateOpenedPaths ns log root query inputs expectedLeaf = true) :
    ∀ index ∈ query.val,
      RecordedPath (globalOnlineNext ns) (logRecords log) .root root
        (0 :: SmzaRp05GlobalOpeningReadback.indexPath index 23)
        (expectedLeaf index) := by
  intro index member
  have allChecked :
      (query.val.toList.all fun position => decide
        (validatePath (globalOnlineNext ns) (logRecords log) .root root
          (0 :: SmzaRp05GlobalOpeningReadback.indexPath position 23) (inputs position) =
            some (expectedLeaf position))) = true := checked
  have selected := (List.all_eq_true.mp allChecked) index (Finset.mem_toList.mpr member)
  have pathChecked :
      validatePath (globalOnlineNext ns) (logRecords log) .root root
        (0 :: SmzaRp05GlobalOpeningReadback.indexPath index 23)
        (inputs index) = some (expectedLeaf index) := by
    simpa only [decide_eq_true_eq] using selected
  exact validatePath_sound _ _ _ _ _ _ _ pathChecked

/-- Canonical RP05 leaf parsing supplies the remaining layout facts.  This
theorem upgrades an executable log validation to `GlobalQueryReadback`; it
does not infer that a Rust accepting run passes `validateOpenedPaths`. -/
noncomputable def canonical_query_readback_of_validated_log
    (ns : Namespace) (log : List (RawInput × RawDigest))
    (root : RawDigest) (query : Query)
    (salt : List HegemonCrypto.CanonicalBytes.Byte)
    (leaves : Position → CurrentLeaf ns salt)
    (inputs : Position → List RawInput)
    (checked : validateOpenedPaths ns log root query inputs
      (fun index => encodeLeaf (leaves index).preamble (leaves index).legacyPayload) = true)
    (indexWord : ∀ index ∈ query.val,
      V8SmzaOracleParser.wordAt (leaves index).legacyPayload 4 = index.val) :
    GlobalQueryReadback ns (logRecords log) root query := by
  exact canonicalQueryReadback ns (logRecords log) root query salt leaves
    (recorded_paths_of_validated_log ns log root query inputs _ checked)
    indexWord

end HegemonCrypto.SmallWood.SmzaRp05VerifierRunReadback
