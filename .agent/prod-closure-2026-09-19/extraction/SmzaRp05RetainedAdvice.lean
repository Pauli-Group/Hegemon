import SmzaRp05TracePrefixes

/-!
# Earlier-role agreement only at the recovered trace's lookups

The extractor retains a sparse set of actual role answers, not a full oracle
table. These congruences connect that retained view to the fixed-other-role
table without assuming equality on unqueried addresses. There are at most
two earlier-role lookups in each chronological prefix.
-/
namespace HegemonCrypto.SmallWood.SmzaRp05RetainedAdvice

open SmzaChallengeStageTargets SmzaRp05LeafNamespace
open SmzaRp05StatementNamespace SmzaRp05TracePrefixes
open scoped Classical

local notation "Statement" => SmzaRp05StatementNamespace.Statement

noncomputable section
set_option autoImplicit false

theorem matrix_label_eq_of_retained_reads
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (left right : EarlierTables model statement .piopMatrix) (trace : Trace)
    (decs : ∀ fpp, payload leafNs .fpp trace = some fpp →
      left .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0) =
        right .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0)) :
    matrixLabel model leafNs statement left trace =
      matrixLabel model leafNs statement right trace := by
  cases parsed : payload leafNs .fpp trace with
  | none => simp [matrixLabel, parsed]
  | some fpp =>
      simp [matrixLabel, parsed, decs fpp parsed]

theorem opening_label_eq_of_retained_reads
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (left right : EarlierTables model statement .piopOpening) (trace : Trace)
    (decs : ∀ fpp, payload leafNs .fpp (child trace 0) = some fpp →
      left .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0) =
        right .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0))
    (matrix : ∀ piop, payload leafNs .piop trace = some piop →
      left .piopMatrix (by decide) (V8SmzaOracleParser.digestAt piop.bytes 0) =
        right .piopMatrix (by decide) (V8SmzaOracleParser.digestAt piop.bytes 0)) :
    openingLabel model leafNs statement left trace =
      openingLabel model leafNs statement right trace := by
  cases piopParsed : payload leafNs .piop trace with
  | none => simp [openingLabel, piopParsed]
  | some piop =>
      cases fppParsed : payload leafNs .fpp (child trace 0) with
      | none =>
          simp [openingLabel, piopParsed, fppParsed]
      | some fpp =>
          simp [openingLabel, piopParsed, fppParsed,
            decs fpp fppParsed, matrix piop piopParsed]

theorem query_labels_eq_of_retained_reads
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (left right : EarlierTables model statement .decsSample) (trace : Trace)
    (decs : ∀ fpp, payload leafNs .fpp (child (child trace 0) 0) = some fpp →
      left .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0) =
        right .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0))
    (opening : ∀ payload, SmzaRp05TracePrefixes.payload leafNs .decs trace =
        some payload →
      left .piopOpening (by decide) (V8SmzaOracleParser.digestAt payload.bytes 0) =
        right .piopOpening (by decide) (V8SmzaOracleParser.digestAt payload.bytes 0)) :
    queryLabels leafNs statement model left trace =
      queryLabels leafNs statement model right trace := by
  cases decsParsed : payload leafNs .decs trace with
  | none => simp [queryLabels, decsParsed]
  | some decsPayload =>
      cases piopParsed : payload leafNs .piop (child trace 0) with
      | none =>
          simp [queryLabels, decsParsed, piopParsed]
      | some piop =>
          cases fppParsed : payload leafNs .fpp (child (child trace 0) 0) with
          | none =>
              simp [queryLabels, decsParsed, piopParsed, fppParsed]
          | some fpp =>
              simp [queryLabels, decsParsed, piopParsed, fppParsed,
                decs fpp fppParsed, opening decsPayload decsParsed]

/-- Only addresses actually used by the chronological trace are compared. -/
def TraceReadAgreement
    (model : RelationModel) (leafNs : Namespace) (statement : Statement) :
    (role : Role) → EarlierTables model statement role →
      EarlierTables model statement role → Trace → Prop
  | .decsMatrix, _, _, _ => True
  | .piopMatrix, left, right, trace =>
      ∀ fpp, payload leafNs .fpp trace = some fpp →
        left .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0) =
          right .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0)
  | .piopOpening, left, right, trace =>
      (∀ fpp, payload leafNs .fpp (child trace 0) = some fpp →
        left .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0) =
          right .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0)) ∧
      (∀ piop, payload leafNs .piop trace = some piop →
        left .piopMatrix (by decide) (V8SmzaOracleParser.digestAt piop.bytes 0) =
          right .piopMatrix (by decide) (V8SmzaOracleParser.digestAt piop.bytes 0))
  | .decsSample, left, right, trace =>
      (∀ fpp, payload leafNs .fpp (child (child trace 0) 0) = some fpp →
        left .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0) =
          right .decsMatrix (by decide) (V8SmzaOracleParser.digestAt fpp.bytes 0)) ∧
      (∀ decs, payload leafNs .decs trace = some decs →
        left .piopOpening (by decide) (V8SmzaOracleParser.digestAt decs.bytes 0) =
          right .piopOpening (by decide) (V8SmzaOracleParser.digestAt decs.bytes 0))

theorem prefix_labels_eq_of_retained_reads
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (role : Role) (left right : EarlierTables model statement role) (trace : Trace)
    (agreement : TraceReadAgreement model leafNs statement role left right trace) :
    prefixLabels model leafNs statement role left trace =
      prefixLabels model leafNs statement role right trace := by
  cases role with
  | decsMatrix => rfl
  | piopMatrix =>
      have same := matrix_label_eq_of_retained_reads model leafNs statement
        left right trace agreement
      simp only [prefixLabels, same]
  | piopOpening =>
      have same := opening_label_eq_of_retained_reads model leafNs statement
        left right trace agreement.1 agreement.2
      simp only [prefixLabels, same]
  | decsSample =>
      have same := query_labels_eq_of_retained_reads model leafNs statement
        left right trace agreement.1 agreement.2
      simp only [prefixLabels, same]

theorem role_labels_eq_of_retained_reads
    (model : RelationModel) (leafNs : Namespace) (statement : Statement)
    (role : Role) (left right : EarlierTables model statement role) (trace : Trace)
    (agreement : TraceReadAgreement model leafNs statement role left right trace) :
    roleLabels model leafNs statement role left trace =
      roleLabels model leafNs statement role right trace := by
  exact congrArg (TypedPrefixLabel.decoded statement)
    (prefix_labels_eq_of_retained_reads model leafNs statement role
      left right trace agreement)

end
end HegemonCrypto.SmallWood.SmzaRp05RetainedAdvice
