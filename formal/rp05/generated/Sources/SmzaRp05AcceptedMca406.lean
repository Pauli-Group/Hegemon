import SmzaRp05AcceptedGlobalQueryReadback
import SmzaRp05ExecutablePcsClosureMca406
import SmzaRp05ExecutablePcsClosureMcaPositionBinding

/-! Same-stage current-profile MCA equations and measured q38 readback.
This uses the complete native 406-coefficient restoration; it does not claim
the older degree-387 `FiveMcaChecks` predicate. -/

namespace HegemonCrypto.SmallWood.SmzaRp05AcceptedMca406

open HegemonCrypto.CanonicalBytes (Byte)
open HegemonCrypto.SmallWood (Goldilocks)
open SmzaRp05GlobalOpeningReadback (GlobalQueryReadback)
open SmzaRp05AcceptedGlobalQueryReadback (accepted_pcs_stages_global_query_readback)
open SmzaRp05DecsResponseProjection
  (DecodedDecsResponseFields FieldRow decodeFieldRow restoredResponsePolynomials)
open SmzaRp05ExecutablePcsClosureDecsChecks
  (successful_hash_fpp_program_has_restoration restored_response_shape_facts)
open SmzaRp05ExecutablePcsClosureStages (PcsStages)
open SmzaRp05ExecutablePcsClosureMca406
  (NativeFiveMcaChecks406 successful_restore_rows_have_406_coefficients
    successful_restore_has_native_five_mca_406)
open SmzaRp05ExecutablePcsClosureMcaPositionBinding
  (pcs_stages_position_binding)
open SmzaRp05PcsHashFppMiddle (gammaRows)
open SmzaRp05FilteredDecoderInstability (RawRecords globalOnlineNext)
open SmzaRp05ExecutableChallengeStage (FieldWord)
open V8SmzaOracleParser (RawDigest)

set_option autoImplicit false
noncomputable section

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

private theorem successful_merkle_input_dimensions
    (salt binding : List Byte) (indexes : List Nat)
    (rows : List (List Goldilocks)) (masks : List (List FieldWord))
    (tapes : List (List Byte)) (paths : List (List RawDigest))
    (pending : Bool) (input : SmzaRp05ExecutableMerkleVerifier.Input)
    (built : SmzaRp05PcsMerklePayload.makeMerkleInput salt binding pending
      indexes rows masks tapes paths = some input) :
    salt.length = 32 ∧ tapes.length = 38 ∧
      ∀ index, index < 38 → (tapes.getD index []).length = 64 := by
  unfold SmzaRp05PcsMerklePayload.makeMerkleInput at built
  split at built
  · simp at built
  · rename_i good
    have tapeCount : tapes.length = 38 := by
      by_contra bad
      exact good (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inl bad))))))
    refine ⟨?_, ?_, ?_⟩
    · by_contra bad
      exact good (Or.inl bad)
    · exact tapeCount
    · intro index within
      have tapeBound : index < tapes.length := by rw [tapeCount]; exact within
      have member : tapes.getD index [] ∈ tapes := by
        rw [List.getD_eq_getElem tapes [] tapeBound]
        exact List.getElem_mem tapeBound
      by_contra bad
      have anyBad : tapes.any (fun tape => decide (tape.length ≠ 64)) = true :=
        List.any_eq_true.mpr ⟨tapes.getD index [], member, decide_eq_true bad⟩
      exact good (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
        (Or.inr (Or.inr (Or.inr anyBad)))))))))

/-- From one accepted PCS-stage object, obtain its actual 406-coefficient
restoration, native five-by-38 equations, q38 evaluation-point binding, and
the same-run measured readback for those exact normalized leaf bytes. -/
theorem accepted_pcs_stages_have_native_mca406_readback
    (ns : SmzaRp05LeafNamespace.Namespace) (pending : Bool)
    (hPiop : RawDigest) (wire : SmzaRp05PcsWireProjection.DecodedMiddleWire)
    (decs : DecodedDecsResponseFields) (points : List Goldilocks)
    (salt binding : List Byte) (statementBinding : List Nat)
    (tapes : List (List Byte)) (paths : List (List RawDigest))
    (oracle : SmzaRp05ExecutableMerkleVerifier.Oracle) (hashFpp : RawDigest)
    (finalPending : Bool)
    (stages : PcsStages ns pending hPiop wire decs points salt binding statementBinding
      tapes paths oracle hashFpp finalPending)
    (clean : finalPending = false) (measured : RawRecords)
    (retained : ∀ stage raw digest,
      (raw, digest) ∈
        (SmzaRp05ExecutableMerkleVerifier.recordedAttempt ns oracle stages.merkleInput).2 →
      (globalOnlineNext ns stage raw).isSome → (raw, digest) ∈ measured) :
    ∃ coordinates : Fin 38 → SmzaQ38McaSourceBinding.Position,
      ∃ query : SmzaQ38McaSourceBinding.Query,
        ∃ claims : GlobalQueryReadback ns measured stages.post.root query,
          ∃ polynomials : List FieldRow,
            restoredResponsePolynomials decs
              (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
              (gammaRows stages.post)
              (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) 140 368 =
                some polynomials ∧
            (∀ j, (coordinates j).val = stages.indexes.getD j.val 0) ∧
            StrictMono coordinates ∧ query.val = Finset.univ.image coordinates ∧
            (∀ j, (claims.leaf (coordinates j)).bytes =
              SmzaRp05PcsMerklePayload.normalizedLeafPayload salt
                (tapes.getD j.val []) (stages.indexes.getD j.val 0)
                (stages.rows.getD j.val []) (decs.maskingEvals.getD j.val [])) ∧
            (∀ j, stages.decsPoints.getD j.val 0 =
              SmzaRp05Q38CurrentRebinding.smz9EvaluationPoint (coordinates j)) ∧
            (∀ polynomialIndex, polynomialIndex < 5 →
              (polynomials.getD polynomialIndex []).length = 406) ∧
            NativeFiveMcaChecks406 salt tapes stages.indexes
              (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
              (gammaRows stages.post) decs.maskingEvals
              (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord) polynomials := by
  obtain ⟨coordinates, query, claims, _index, ordered, image, _input, leafBytes,
      coordinateIndex, payloadEq⟩ := accepted_pcs_stages_global_query_readback
    ns pending hPiop wire decs points salt binding statementBinding tapes paths oracle
    hashFpp finalPending stages clean measured retained
  obtain ⟨polynomials, restoreSuccess⟩ := successful_hash_fpp_program_has_restoration
    stages.post.root decs
    (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
    (gammaRows stages.post)
    (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
    140 368 statementBinding stages.hashProgram stages.responseBuilt
  have layout := successful_merkle_input_dimensions salt binding stages.indexes
    stages.rows decs.maskingEvals tapes paths stages.sampledPending
    stages.merkleInput stages.inputBuilt
  have shape := restored_response_shape_facts decs
    (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
    (gammaRows stages.post) (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
    140 368 polynomials restoreSuccess
  have rowShape : ∀ index, index < 38 →
      (decodeFieldRow
        ((stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord).getD
          index [])).length = 140 := by
    intro index within
    have member :
        (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord).getD
          index [] ∈
          stages.rows.map (fun row => row.map SmzaRp05ExecutableRestore.toWord) := by
      rw [List.getD_eq_getElem _ [] (by rw [shape.2.2.2.2.1]; exact within)]
      exact List.getElem_mem (by rw [shape.2.2.2.2.1]; exact within)
    simpa [decodeFieldRow] using shape.2.2.2.2.2.2.2.1 _ member
  have gammaShape : ∀ polynomialIndex, polynomialIndex < 5 →
      (decodeFieldRow ((gammaRows stages.post).getD polynomialIndex [])).length = 140 := by
    intro polynomialIndex within
    have member : (gammaRows stages.post).getD polynomialIndex [] ∈ gammaRows stages.post := by
      rw [List.getD_eq_getElem _ [] (by rw [shape.2.2.2.1]; exact within)]
      exact List.getElem_mem (by rw [shape.2.2.2.1]; exact within)
    simpa [decodeFieldRow] using shape.2.2.2.2.2.2.1 _ member
  have maskShape : ∀ index, index < 38 →
      (decs.maskingEvals.getD index []).length = 5 := by
    intro index within
    have member : decs.maskingEvals.getD index [] ∈ decs.maskingEvals := by
      rw [List.getD_eq_getElem _ [] (by rw [shape.2.1]; exact within)]
      exact List.getElem_mem (by rw [shape.2.1]; exact within)
    exact shape.2.2.2.2.2.1 _ member
  have native := successful_restore_has_native_five_mca_406 decs
    (stages.rows.map fun row => row.map SmzaRp05ExecutableRestore.toWord)
    (gammaRows stages.post)
    (stages.decsPoints.map SmzaRp05ExecutableRestore.toWord)
    polynomials restoreSuccess salt tapes stages.indexes layout.1
    (layout.2.2) rowShape gammaShape maskShape
  refine ⟨coordinates, query, claims, polynomials, restoreSuccess, coordinateIndex,
    ordered, image, payloadEq, ?_, native.1, native.2⟩
  · exact pcs_stages_position_binding ns pending hPiop wire decs points salt binding
      statementBinding tapes paths oracle hashFpp finalPending stages coordinates coordinateIndex

end
end HegemonCrypto.SmallWood.SmzaRp05AcceptedMca406
