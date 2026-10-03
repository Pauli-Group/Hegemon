import SmzaRp05VerifierRunReadback

/-! Lift executable raw-log path validation into the SAME measured record
relation used by extraction. Extra adversary/history records are permitted;
we do not equate a verifier suffix log with the entire physical database.

This establishes the measured-record transport only. Rust acceptance still
must be shown to emit candidate paths passing `validateOpenedPaths`, and the
measurement instrument must establish raw-log membership in its branch.
Neither claim is silently taken from an audit summary boolean. -/
/-! Status (source-only; not compiled): this is NOT literal verifier
acceptance-to-readback closure. The exact remaining premises are:
1. Accepted Rust `decs_recompute_root_with_leaf_binding` (engine :11895),
   recorded through `sha512_raw_domain_digest` (:4292) and the frontend
   evidence entrypoint (:875), must construct `inputs`/canonical v2 leaves
   and imply `validateOpenedPaths = true` plus the opened-index equation.
   `VerifierRunReadback.validateOpenedPaths` (:108) is not called or formally
   refined by those Rust entrypoints yet.
2. The actual X-measurement/retention instrument must prove `supported` for
   parser-visible pairs in that same suffix log and same measured branch.
   This does not follow from log recording or raw SHA determinism alone.
The abstract acceptance conjunction in `AbstractVerifierBadRole` (:31) is
not used. Line anchors describe the source snapshot at this edit. -/
namespace HegemonCrypto.SmallWood.SmzaRp05MeasuredLogReadback

open SmzaRecordedTracePath V8Smz9CoherentMerkleGeometry
open SmzaRp05VerifierRunReadback SmzaRp05GlobalOpeningReadback
open SmzaRp05FilteredDecoderInstability SmzaRp05LeafNamespace
open SmzaQ38McaSourceBinding
set_option autoImplicit false

abbrev Stage := V8SmzaOracleParser.Stage
abbrev RawInput := V8SmzaOracleParser.RawInput
abbrev RawDigest := V8SmzaOracleParser.RawDigest
abbrev RawRecords := V8Smz9CoherentMerkleGeometry.Records RawInput RawDigest

theorem recorded_path_mono
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (left right : RawRecords) (included : left ⊆ right)
    (stage : Stage) (target : RawDigest) (path : List Nat) (leaf : RawInput)
    (recorded : RecordedPath next left stage target path leaf) :
    RecordedPath next right stage target path leaf := by
  induction recorded with
  | here stage target input member valid =>
      exact RecordedPath.here stage target input (included member) valid
  | step stage target input edges index childStage childTarget rest leaf
      member parsed edge below ih =>
      exact RecordedPath.step stage target input edges index childStage childTarget
        rest leaf (included member) parsed edge ih

theorem recorded_path_of_parser_supported_inputs
    (next : Stage → RawInput → Option (List (Stage × RawDigest)))
    (left right : RawRecords)
    (supported : ∀ stage input output, (input, output) ∈ left →
      (next stage input).isSome → (input, output) ∈ right)
    (stage : Stage) (target : RawDigest) (path : List Nat) (leaf : RawInput)
    (recorded : RecordedPath next left stage target path leaf) :
    RecordedPath next right stage target path leaf := by
  induction recorded with
  | here stage target input member valid =>
      exact RecordedPath.here stage target input (supported stage input target member valid) valid
  | step stage target input edges index childStage childTarget rest leaf
      member parsed edge below ih =>
      exact RecordedPath.step stage target input edges index childStage childTarget rest leaf
        (supported stage input target member (by simp [parsed])) parsed edge ih

/-- The physical support premise concerns only parser-visible Merkle/wrapper
records. Challenge counter blocks are grouped elsewhere and need not occur
as raw addresses in this measured record relation. No database equality,
successful extraction or AcceptedChecks/execution certificate is assumed. -/
noncomputable def canonical_query_readback_on_same_measured_records
    (ns : Namespace) (log : List (RawInput × RawDigest))
    (measured : RawRecords)
    (supported : ∀ stage input output, (input, output) ∈ log →
      (globalOnlineNext ns stage input).isSome → (input, output) ∈ measured)
    (root : RawDigest) (query : Query)
    (salt : List HegemonCrypto.CanonicalBytes.Byte)
    (leaves : Position → CurrentLeaf ns salt)
    (inputs : Position → List RawInput)
    (checked : validateOpenedPaths ns log root query inputs
      (fun index => encodeLeaf (leaves index).preamble (leaves index).legacyPayload) = true)
    (indexWord : ∀ index ∈ query.val,
      V8SmzaOracleParser.wordAt (leaves index).legacyPayload 4 = index.val) :
    GlobalQueryReadback ns measured root query := by
  apply canonicalQueryReadback ns measured root query salt leaves
  · intro index member
    apply recorded_path_of_parser_supported_inputs
      (globalOnlineNext ns) (logRecords log) measured
      (fun stage input output member valid =>
        supported stage input output (by simpa [logRecords] using member) valid)
      .root root (0 :: SmzaRp05GlobalOpeningReadback.indexPath index 23) _
    exact recorded_paths_of_validated_log ns log root query inputs _ checked index member
  · exact indexWord

end HegemonCrypto.SmallWood.SmzaRp05MeasuredLogReadback
