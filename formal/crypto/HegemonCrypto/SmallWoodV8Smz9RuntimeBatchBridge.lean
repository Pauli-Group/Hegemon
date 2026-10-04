import HegemonCrypto.SmallWoodV8Smz9RuntimeDistribution
import Mathlib.Data.Vector.Basic
import Mathlib.Logic.Equiv.Prod

namespace HegemonCrypto.SmallWood.V8Smz9RuntimeBatchBridge

open V8Smz9RuntimeRandomness V8Smz9RuntimeDistribution

/-- The finite first-accept scanner stops exactly when the requested count is
    exhausted. In particular, no candidate may follow that stopping point. -/
def ExactPrefix (remaining : Nat) : List RawWord → Prop
  | [] => remaining = 0
  | candidate :: rest => 0 < remaining ∧ ExactPrefix
      (if candidate.val < fieldModulus then remaining - 1 else remaining) rest

/-- Actual remaining-count batch widths and updates, with no zero-width or
    post-completion round. This models successful fills only, not provider/OS behavior. -/
def ValidBatches (remaining : Nat) : List (List RawWord) → Prop
  | [] => remaining = 0
  | buffer :: rounds => 0 < remaining ∧ buffer.length = remaining ∧
      ValidBatches (remaining - (scanAccepted buffer).length) rounds

abbrev BatchTrace (count : Nat) := { rounds : List (List RawWord) // ValidBatches count rounds }
abbrev RawPrefix (count : Nat) := { raw : List RawWord // ExactPrefix count raw }
abbrev SegmentVector (count : Nat) := List.Vector TerminatingSegment count

theorem scan_length_le (raw : List RawWord) : (scanAccepted raw).length ≤ raw.length := by
  induction raw with
  | nil => rfl
  | cons candidate rest ih =>
      simp only [scanAccepted, List.length_cons]
      split <;> (try simp only [List.length_cons]) <;> omega

theorem exact_zero_iff (raw : List RawWord) : ExactPrefix 0 raw ↔ raw = [] := by
  cases raw <;> simp [ExactPrefix]

theorem exact_scan_length {n : Nat} {raw : List RawWord} (h : ExactPrefix n raw) :
    (scanAccepted raw).length = n := by
  induction raw generalizing n with
  | nil => simpa [ExactPrefix, scanAccepted] using h.symm
  | cons candidate rest ih =>
      obtain ⟨hpositive, hrest⟩ := h
      by_cases hc : candidate.val < fieldModulus
      · simp only [if_pos hc] at hrest
        have hi := ih hrest
        simp only [scanAccepted, decodeCandidate, hc, ↓reduceDIte, List.length_cons]
        omega
      · simp only [if_neg hc] at hrest
        simpa only [scanAccepted, decodeCandidate, hc, ↓reduceDIte] using ih hrest

theorem exact_append_iff (chunk rest : List RawWord) (n : Nat)
    (hwidth : chunk.length ≤ n) :
    ExactPrefix n (chunk ++ rest) ↔
      ExactPrefix (n - (scanAccepted chunk).length) rest := by
  induction chunk generalizing n with
  | nil => simp [scanAccepted]
  | cons candidate chunk ih =>
      have hn : 0 < n := by simpa using lt_of_lt_of_le (by simp : 0 < (candidate :: chunk).length) hwidth
      by_cases hc : candidate.val < fieldModulus
      · have hw : chunk.length ≤ n - 1 := by simp only [List.length_cons] at hwidth; omega
        simp only [List.cons_append, ExactPrefix, hc, ↓reduceIte, hn, true_and,
          scanAccepted, decodeCandidate, ↓reduceDIte, List.length_cons]
        have harith : n - 1 - (scanAccepted chunk).length =
            n - ((scanAccepted chunk).length + 1) := by omega
        simpa only [harith] using ih (n - 1) hw
      · have hw : chunk.length ≤ n := by simp only [List.length_cons] at hwidth; omega
        simp only [List.cons_append, ExactPrefix, hc, ↓reduceIte, hn, true_and,
          scanAccepted, decodeCandidate, ↓reduceDIte]
        exact ih n hw

theorem valid_batches_exact {n : Nat} {rounds : List (List RawWord)}
    (h : ValidBatches n rounds) : ExactPrefix n rounds.flatten := by
  induction rounds generalizing n with
  | nil => exact h
  | cons buffer rounds ih =>
      obtain ⟨_, hwidth, htail⟩ := h
      apply (exact_append_iff buffer rounds.flatten n (by omega)).2
      exact ih htail

theorem exact_has_batches (raw : List RawWord) :
    ∀ n, ExactPrefix n raw → ∃ rounds, ValidBatches n rounds ∧ rounds.flatten = raw := by
  induction raw using (measure (fun xs : List RawWord => xs.length)).wf.induction with
  | _ raw ih =>
      intro n h
      by_cases hn : n = 0
      · subst n
        have hnil := (exact_zero_iff raw).1 h
        exact ⟨[], rfl, hnil.symm⟩
      · have hnpos : 0 < n := by omega
        have hlength : n ≤ raw.length := by
          rw [← exact_scan_length h]
          exact scan_length_le raw
        have hwidth : (raw.take n).length = n := by simp [List.length_take, Nat.min_eq_left hlength]
        have hrest : ExactPrefix (n - (scanAccepted (raw.take n)).length) (raw.drop n) := by
          apply (exact_append_iff (raw.take n) (raw.drop n) n (by omega)).1
          simpa using h
        have hshort : (raw.drop n).length < raw.length := by
          simp only [List.length_drop]
          omega
        obtain ⟨rounds, hrounds, hflatten⟩ := ih (raw.drop n) hshort _ hrest
        refine ⟨raw.take n :: rounds, ⟨hnpos, hwidth, hrounds⟩, ?_⟩
        simp only [List.flatten_cons, hflatten, List.take_append_drop]

theorem valid_batches_unique {n : Nat} {left right : List (List RawWord)}
    (hl : ValidBatches n left) (hr : ValidBatches n right)
    (hraw : left.flatten = right.flatten) : left = right := by
  induction left generalizing n right with
  | nil =>
      cases right with
      | nil => rfl
      | cons buffer rounds =>
          have hn : n = 0 := hl
          have hp : 0 < n := hr.1
          omega
  | cons buffer rounds ih =>
      obtain ⟨hpositive, hwidth, htail⟩ := hl
      cases right with
      | nil => have hn : n = 0 := hr; omega
      | cons other rest =>
          obtain ⟨_, hotherwidth, hothertail⟩ := hr
          have hhead := congrArg (List.take n) hraw
          simp only [List.flatten_cons, ← hwidth, List.take_left] at hhead
          have hhead' : buffer = other := by
            simpa only [hwidth, ← hotherwidth, List.take_left] using hhead
          subst other
          have htails : rounds.flatten = rest.flatten := by
            exact List.append_cancel_left (by simpa only [List.flatten_cons] using hraw)
          exact congrArg (List.cons buffer) (ih htail hothertail htails)

noncomputable def batchPrefixEquiv (n : Nat) : BatchTrace n ≃ RawPrefix n where
  toFun batch := ⟨batch.val.flatten, valid_batches_exact batch.property⟩
  invFun raw := ⟨Classical.choose (exact_has_batches raw.val n raw.property),
    (Classical.choose_spec (exact_has_batches raw.val n raw.property)).1⟩
  left_inv batch := by
    apply Subtype.ext
    apply valid_batches_unique
    · exact (Classical.choose_spec (exact_has_batches batch.val.flatten n
        (valid_batches_exact batch.property))).1
    · exact batch.property
    · exact (Classical.choose_spec (exact_has_batches batch.val.flatten n
        (valid_batches_exact batch.property))).2
  right_inv raw := by
    apply Subtype.ext
    exact (Classical.choose_spec (exact_has_batches raw.val n raw.property)).2

def parseSegments : List RawWord → Option (List TerminatingSegment)
  | [] => some []
  | candidate :: rest =>
      if hc : candidate.val < fieldModulus then
        (parseSegments rest).map fun segments => ([], ⟨candidate.val, hc⟩) :: segments
      else
        match parseSegments rest with
        | some ((rejected, coin) :: segments) =>
            some ((⟨candidate, Nat.le_of_not_gt hc⟩ :: rejected, coin) :: segments)
        | _ => none

theorem parse_rejected_segment (rejected : List RejectedRawWord) (coin : IdealFieldCoin)
    (raw : List RawWord) (segments : List TerminatingSegment)
    (hrest : parseSegments raw = some segments) :
    parseSegments (rejected.map Subtype.val ++ encodeCoin coin :: raw) =
      some ((rejected, coin) :: segments) := by
  induction rejected with
  | nil => simp [parseSegments, encodeCoin, coin.isLt, hrest]
  | cons candidate rejected ih =>
      simp only [List.map_cons, List.cons_append, parseSegments,
        dif_neg (Nat.not_lt.mpr candidate.property), ih]

theorem parse_terminating_candidates (segments : List TerminatingSegment) :
    parseSegments (terminatingTraceCandidates segments) = some segments := by
  induction segments with
  | nil => rfl
  | cons segment segments ih =>
      rcases segment with ⟨rejected, coin⟩
      change parseSegments ((rejected.map Subtype.val ++ [encodeCoin coin]) ++
        terminatingTraceCandidates segments) = _
      rw [List.append_assoc]
      exact parse_rejected_segment rejected coin _ _ ih

theorem terminating_candidates_injective : Function.Injective terminatingTraceCandidates := by
  intro left right h
  have hp := congrArg parseSegments h
  simpa only [parse_terminating_candidates, Option.some.injEq] using hp

theorem exact_rejected_segment (rejected : List RejectedRawWord) (coin : IdealFieldCoin)
    (raw : List RawWord) (n : Nat) :
    ExactPrefix (n + 1) (rejected.map Subtype.val ++ encodeCoin coin :: raw) ↔
      ExactPrefix n raw := by
  induction rejected with
  | nil => simp [ExactPrefix, encodeCoin, coin.isLt]
  | cons candidate rejected ih =>
      simpa only [List.map_cons, List.cons_append, ExactPrefix,
        if_neg (Nat.not_lt.mpr candidate.property), Nat.zero_lt_succ, true_and] using ih

theorem terminating_candidates_exact (segments : List TerminatingSegment) :
    ExactPrefix segments.length (terminatingTraceCandidates segments) := by
  induction segments with
  | nil => rfl
  | cons segment segments ih =>
      rcases segment with ⟨rejected, coin⟩
      change ExactPrefix (segments.length + 1)
        ((rejected.map Subtype.val ++ [encodeCoin coin]) ++ terminatingTraceCandidates segments)
      rw [List.append_assoc]
      exact (exact_rejected_segment rejected coin _ _).2 ih

theorem exact_has_segments (raw : List RawWord) :
    ∀ n, ExactPrefix n raw →
      ∃ segments, segments.length = n ∧ terminatingTraceCandidates segments = raw := by
  induction raw with
  | nil =>
      intro n h
      exact ⟨[], h.symm, rfl⟩
  | cons candidate rest ih =>
      intro n h
      obtain ⟨hpositive, hrest⟩ := h
      by_cases hc : candidate.val < fieldModulus
      · simp only [if_pos hc] at hrest
        obtain ⟨segments, hlength, hraw⟩ := ih (n - 1) hrest
        let coin : IdealFieldCoin := ⟨candidate.val, hc⟩
        have hencode : encodeCoin coin = candidate := by apply Fin.ext; rfl
        refine ⟨([], coin) :: segments, ?_, ?_⟩
        · simp only [List.length_cons]
          omega
        · change encodeCoin coin :: terminatingTraceCandidates segments = candidate :: rest
          rw [hencode, hraw]
      · simp only [if_neg hc] at hrest
        obtain ⟨segments, hlength, hraw⟩ := ih n hrest
        cases segments with
        | nil => simp only [List.length_nil] at hlength; omega
        | cons segment segments =>
            rcases segment with ⟨rejected, coin⟩
            let word : RejectedRawWord := ⟨candidate, Nat.le_of_not_gt hc⟩
            refine ⟨(word :: rejected, coin) :: segments, hlength, ?_⟩
            change candidate :: terminatingTraceCandidates ((rejected, coin) :: segments) =
              candidate :: rest
            rw [hraw]

noncomputable def segmentPrefixEquiv (n : Nat) : SegmentVector n ≃ RawPrefix n where
  toFun segments := ⟨terminatingTraceCandidates segments.val, by
    simpa only [segments.property] using terminating_candidates_exact segments.val⟩
  invFun raw := ⟨Classical.choose (exact_has_segments raw.val n raw.property),
    (Classical.choose_spec (exact_has_segments raw.val n raw.property)).1⟩
  left_inv segments := by
    apply Subtype.ext
    apply terminating_candidates_injective
    exact (Classical.choose_spec (exact_has_segments
      (terminatingTraceCandidates segments.val) n (by
        simpa only [segments.property] using terminating_candidates_exact segments.val))).2
  right_inv raw := by
    apply Subtype.ext
    exact (Classical.choose_spec (exact_has_segments raw.val n raw.property)).2

/-- Re-indexing only: the existing first-accept trace's rejection tuple becomes
    its list, and its accepted raw word becomes the same canonical coin. -/
def traceSegmentEquiv : IidUniformTerminatingTrace ≃ TerminatingSegment :=
  (Equiv.sigmaProdDistrib (fun n : Nat => Fin n → RejectedRawWord) AcceptedRawWord).symm.trans
    (Equiv.prodCongr List.equivSigmaTuple.symm acceptedRawWordEquiv.symm)

theorem trace_segment_candidates (trace : IidUniformTerminatingTrace) :
    segmentCandidates (traceSegmentEquiv trace) = iidUniformTraceCandidates trace := by
  rcases trace with ⟨attempt, rejected, accepted⟩
  rfl

theorem trace_segment_output (trace : IidUniformTerminatingTrace) :
    (traceSegmentEquiv trace).2 = iidUniformTraceOutput trace := rfl

def vectorSegmentsEquiv (n : Nat) :
    (Fin n → IidUniformTerminatingTrace) ≃ SegmentVector n :=
  (Equiv.piCongrRight fun _ : Fin n => traceSegmentEquiv).trans
    (Equiv.vectorEquivFin TerminatingSegment n).symm

noncomputable def firstPrefixEquiv (n : Nat) :
    (Fin n → IidUniformTerminatingTrace) ≃ RawPrefix n :=
  (vectorSegmentsEquiv n).trans (segmentPrefixEquiv n)

def firstTraceCandidates {n : Nat} (traces : Fin n → IidUniformTerminatingTrace) :
    List RawWord := (List.ofFn traces).flatMap iidUniformTraceCandidates

theorem vector_segments_val {n : Nat} (traces : Fin n → IidUniformTerminatingTrace) :
    (vectorSegmentsEquiv n traces).val = List.ofFn (fun i => traceSegmentEquiv (traces i)) := by
  exact List.Vector.toList_ofFn _

theorem first_prefix_raw {n : Nat} (traces : Fin n → IidUniformTerminatingTrace) :
    (firstPrefixEquiv n traces).val = firstTraceCandidates traces := by
  change terminatingTraceCandidates (vectorSegmentsEquiv n traces).val = _
  rw [vector_segments_val]
  unfold terminatingTraceCandidates
  rw [List.ofFn_comp' traces traceSegmentEquiv]
  simp only [List.flatMap_map, trace_segment_candidates, firstTraceCandidates]

/-- Constructed bijection, not a premise identifying runtime and ideal traces. -/
noncomputable def batchFirstAcceptEquiv (n : Nat) :
    BatchTrace n ≃ (Fin n → IidUniformTerminatingTrace) :=
  (batchPrefixEquiv n).trans (firstPrefixEquiv n).symm

theorem batch_first_accept_preserves_raw {n : Nat} (batch : BatchTrace n) :
    firstTraceCandidates (batchFirstAcceptEquiv n batch) = batch.val.flatten := by
  rw [← first_prefix_raw]
  change ((firstPrefixEquiv n)
    ((firstPrefixEquiv n).symm (batchPrefixEquiv n batch))).val = _
  rw [Equiv.apply_symm_apply]
  rfl

theorem batch_first_accept_preserves_length {n : Nat} (batch : BatchTrace n) :
    (firstTraceCandidates (batchFirstAcceptEquiv n batch)).length =
      batch.val.flatten.length := congrArg List.length (batch_first_accept_preserves_raw batch)

theorem first_trace_scan {n : Nat} (traces : Fin n → IidUniformTerminatingTrace) :
    scanAccepted (firstTraceCandidates traces) =
      List.ofFn (fun i => iidUniformTraceOutput (traces i)) := by
  rw [← first_prefix_raw]
  change scanAccepted (terminatingTraceCandidates (vectorSegmentsEquiv n traces).val) = _
  rw [vector_segments_val]
  rw [scan_terminating_trace_returns_exact_outputs]
  simp only [terminatingTraceOutputs, List.map_ofFn, Function.comp_def, trace_segment_output]

theorem batch_first_accept_preserves_outputs {n : Nat} (batch : BatchTrace n) :
    scanAccepted batch.val.flatten =
      List.ofFn (fun i => iidUniformTraceOutput (batchFirstAcceptEquiv n batch i)) := by
  rw [← batch_first_accept_preserves_raw batch]
  exact first_trace_scan _

theorem batch_round_no_overshoot {n : Nat} {buffer : List RawWord}
    {rounds : List (List RawWord)} (h : ValidBatches n (buffer :: rounds)) :
    (scanAccepted buffer).length ≤ n := by
  rw [← h.2.1]
  exact scan_length_le buffer

theorem zero_batch_has_no_rounds (batch : BatchTrace 0) : batch.val = [] := by
  cases h : batch.val with
  | nil => rfl
  | cons buffer rounds =>
      have hp : 0 < 0 := by have hv := batch.property; rw [h] at hv; exact hv.1
      omega


end HegemonCrypto.SmallWood.V8Smz9RuntimeBatchBridge
