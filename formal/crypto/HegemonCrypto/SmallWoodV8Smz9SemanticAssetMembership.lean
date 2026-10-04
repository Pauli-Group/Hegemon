import HegemonCrypto.SmallWoodV8Smz9SemanticDecoder
import HegemonCrypto.SmallWoodV8Smz9ProgramPolynomials
import Mathlib.Data.List.GetD

/-! Active-note asset membership and derived selectors from the actual source
program. No decoder-success or typed-witness-shape premise is introduced. -/

namespace HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership

open Hegemon.Transaction.Poseidon2V8SemanticSpecification
open Hegemon.Transaction.Poseidon2V8RelationProgram
  (FieldExpression ExpressionProgram packedWitnessLaneRows)
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
open HegemonCrypto.SmallWood.V8Smz9SemanticBinding
open HegemonCrypto.SmallWood.V8Smz9SemanticDenseRange
open HegemonCrypto.SmallWood.V8Smz9SemanticDecoder
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
  (fieldAt fieldAt_eq expressionField expressionField_congr_prior fieldAt_refines_source)

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

theorem project_selectors_active_one_hot
    (statement : V8PublicStatement) (active : Nat) (note : V8NoteOpening)
    (assetLength : statement.balanceAssets.length = 4)
    (activeNe : active ≠ 0)
    (member : ∃ asset, asset ∈ statement.balanceAssets ∧
      asset = note.assetId ∧ asset ≠ balancePaddingAssetId) :
    OneHotSelectorForAsset active note
      (projectSelectors active note.assetId statement) statement.balanceAssets := by
  let predicate := fun candidate : Nat =>
    candidate == note.assetId && candidate != balancePaddingAssetId
  let slot := statement.balanceAssets.findIdx predicate
  have existsMatch : ∃ asset, asset ∈ statement.balanceAssets ∧ predicate asset := by
    obtain ⟨asset, mem, eq, nonpadding⟩ := member
    have noteNonpadding : note.assetId ≠ balancePaddingAssetId := by
      simpa only [eq] using nonpadding
    exact ⟨asset, mem, by simp [predicate, eq, noteNonpadding]⟩
  have found : selectorIndex statement.balanceAssets note.assetId = some slot :=
    List.findIdx?_eq_some_of_exists existsMatch
  have foundRaw : statement.balanceAssets.findIdx? predicate = some slot := found
  obtain ⟨bound, matched, _⟩ := List.findIdx?_eq_some_iff_getElem.mp foundRaw
  have slotBound : slot < 4 := by omega
  have assetAt : wordAt statement.balanceAssets slot = note.assetId := by
    have equal : statement.balanceAssets[slot] = note.assetId := by
      have both : statement.balanceAssets[slot] = note.assetId ∧
          statement.balanceAssets[slot] ≠ balancePaddingAssetId := by
        simpa [predicate] using matched
      exact both.1
    simpa only [wordAt, List.getD_eq_getElem?_getD,
      List.getElem?_eq_getElem bound, Option.getD_some] using equal
  have selected : projectSelectors active note.assetId statement =
      (List.range 4).map (fun index => if slot = index then 1 else 0) := by
    simp [projectSelectors, activeNe, found]
  have cases : slot = 0 ∨ slot = 1 ∨ slot = 2 ∨ slot = 3 := by omega
  refine ⟨by simp [projectSelectors, balanceSlotCount], ?_, ?_⟩
  · intro selector mem
    rw [selected] at mem
    obtain ⟨index, _, rfl⟩ := List.mem_map.mp mem
    by_cases same : slot = index <;> simp [same, BooleanWord]
  · rw [if_neg activeNe]
    refine ⟨?_, slot, by simpa [balanceSlotCount] using slotBound, ?_, assetAt⟩
    · rw [selected]
      rcases cases with h | h | h | h <;> simp [h, List.range_succ]
    · rw [selected]
      rcases cases with h | h | h | h <;> simp [h, wordAt, List.range_succ]

structure AssetRoot where
  note : Nat
  row : Nat
  differences : List Nat
  selectors : List Nat
  product01 : Nat
  product012 : Nat
  product0123 : Nat
  root : Nat
deriving DecidableEq, Repr, Inhabited

def assetRoots : List AssetRoot :=
  [⟨0, 1, [904, 907, 910, 913], [906, 908, 911, 914], 909, 912, 915, 916⟩,
   ⟨1, 35, [981, 983, 986, 989], [982, 984, 987, 990], 985, 988, 991, 992⟩,
   ⟨2, 69, [993, 995, 998, 1001], [994, 996, 999, 1002], 997, 1000, 1003, 1004⟩,
   ⟨3, 81, [1012, 1014, 1017, 1020], [1013, 1015, 1018, 1021],
     1016, 1019, 1022, 1023⟩]

def AssetRoot.Valid (entry : AssetRoot) : Prop :=
  entry.note < 4 ∧ entry.row < 686 ∧
    entry.row * 64 = densePrivateAddress entry.note + 64 ∧
    exactNonlinearExpressions[1]? = some (.constant 1) ∧
    exactNonlinearExpressions[905]? = some (.constant balancePaddingAssetId) ∧
    exactNonlinearExpressions[4 + entry.note]? = some (.publicWord entry.note) ∧
    exactNonlinearExpressions[124 + entry.row]? = some (.witnessRow entry.row) ∧
    (∀ slot, slot ∈ List.range 4 →
      exactNonlinearExpressions[58 + slot]? = some (.publicWord (54 + slot)) ∧
      exactNonlinearExpressions[entry.differences.getD slot 0]? =
        some (.sub (124 + entry.row) (58 + slot)) ∧
      exactNonlinearExpressions[entry.selectors.getD slot 0]? =
        some (.selectEqual (58 + slot) 905 1 (entry.differences.getD slot 0))) ∧
    exactNonlinearExpressions[entry.product01]? =
      some (.mul (entry.selectors.getD 0 0) (entry.selectors.getD 1 0)) ∧
    exactNonlinearExpressions[entry.product012]? =
      some (.mul entry.product01 (entry.selectors.getD 2 0)) ∧
    exactNonlinearExpressions[entry.product0123]? =
      some (.mul entry.product012 (entry.selectors.getD 3 0)) ∧
    exactNonlinearExpressions[entry.root]? =
      some (.mul (4 + entry.note) entry.product0123) ∧ entry.root ∈ exactNonlinearRoots

instance (entry : AssetRoot) : Decidable entry.Valid := by
  unfold AssetRoot.Valid
  infer_instance

theorem exact_asset_roots_valid : ∀ entry, entry ∈ assetRoots → entry.Valid := by
  have checked : assetRoots.all (fun entry => decide entry.Valid) = true := by decide
  simpa only [List.all_eq_true, decide_eq_true_eq] using checked

noncomputable section

theorem actual_node_field_equation (pub rows : Nat → F) {node : Nat}
    {expression : FieldExpression}
    (found : exactNonlinearExpressions[node]? = some expression) :
    fieldAt exactNonlinearExpressions pub rows node =
      expressionField pub rows (fieldAt exactNonlinearExpressions pub rows) expression := by
  rw [fieldAt_eq, found]
  apply expressionField_congr_prior pub rows _ _ node expression
    (hgv8rp03_nonlinear_expression_program_is_canonical.1 node expression found)
  intro i bound
  simp only [if_pos bound]

def assetFactor (asset candidate : F) : F :=
  if candidate = (balancePaddingAssetId : F) then 1 else asset - candidate

theorem actual_asset_root_formula (entry : AssetRoot) (valid : entry.Valid)
    (pub rows : Nat → F) :
    fieldAt exactNonlinearExpressions pub rows entry.root =
      pub entry.note *
        (((assetFactor (rows entry.row) (pub 54) * assetFactor (rows entry.row) (pub 55)) *
          assetFactor (rows entry.row) (pub 56)) * assetFactor (rows entry.row) (pub 57)) := by
  obtain ⟨_, _, _, oneNode, paddingNode, flagNode, rowNode, slotNodes,
    product01Node, product012Node, product0123Node, rootNode, _⟩ := valid
  have one := actual_node_field_equation pub rows oneNode
  have padding := actual_node_field_equation pub rows paddingNode
  have flag := actual_node_field_equation pub rows flagNode
  have row := actual_node_field_equation pub rows rowNode
  simp only [expressionField, Nat.cast_one] at one padding flag row
  have selectors : ∀ slot, slot < 4 →
      fieldAt exactNonlinearExpressions pub rows (entry.selectors.getD slot 0) =
        assetFactor (rows entry.row) (pub (54 + slot)) := by
    intro slot bound
    obtain ⟨publicNode, differenceNode, selectorNode⟩ := slotNodes slot (List.mem_range.mpr bound)
    have pubValue := actual_node_field_equation pub rows publicNode
    have difference := actual_node_field_equation pub rows differenceNode
    have selector := actual_node_field_equation pub rows selectorNode
    simp only [expressionField] at pubValue difference selector
    rw [row, pubValue] at difference
    simpa only [assetFactor, pubValue, padding, one, difference] using selector
  have product01 := actual_node_field_equation pub rows product01Node
  have product012 := actual_node_field_equation pub rows product012Node
  have product0123 := actual_node_field_equation pub rows product0123Node
  have root := actual_node_field_equation pub rows rootNode
  simp only [expressionField] at product01 product012 product0123 root
  rw [flag, product0123, product012, product01,
    selectors 0 (by decide), selectors 1 (by decide), selectors 2 (by decide),
    selectors 3 (by decide)] at root
  exact root

theorem asset_factor_zero {asset candidate : F} (zero : assetFactor asset candidate = 0) :
    candidate ≠ (balancePaddingAssetId : F) ∧ asset = candidate := by
  by_cases padding : candidate = (balancePaddingAssetId : F)
  · simp [assetFactor, padding] at zero
  · exact ⟨padding, sub_eq_zero.mp (by simpa only [assetFactor, if_neg padding] using zero)⟩

theorem four_asset_factors_zero {asset : F} {candidates : Nat → F}
    (zero : ((assetFactor asset (candidates 0) * assetFactor asset (candidates 1)) *
      assetFactor asset (candidates 2)) * assetFactor asset (candidates 3) = 0) :
    ∃ slot, slot < 4 ∧ candidates slot ≠ (balancePaddingAssetId : F) ∧ asset = candidates slot := by
  rcases mul_eq_zero.mp zero with prior | last
  · rcases mul_eq_zero.mp prior with pair | third
    · rcases mul_eq_zero.mp pair with first | second
      · exact ⟨0, by decide, asset_factor_zero first⟩
      · exact ⟨1, by decide, asset_factor_zero second⟩
    · exact ⟨2, by decide, asset_factor_zero third⟩
  · exact ⟨3, by decide, asset_factor_zero last⟩

theorem accepted_active_asset_root_member {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    (entry : AssetRoot) (valid : entry.Valid)
    (active : publicWords.getD entry.note 0 = 1) :
    ∃ slot, slot < 4 ∧ publicWords.getD (54 + slot) 0 ≠ balancePaddingAssetId ∧
      packedWord packed (densePrivateAddress entry.note + 64) = publicWords.getD (54 + slot) 0 := by
  have validCopy := valid
  obtain ⟨_, rowBound, address, _, _, _, _, _, _, _, _, _, rootMember⟩ := validCopy
  obtain ⟨values, evaluated, rootZero⟩ :=
    Poseidon2V8ExpressionRootSemantics.acceptance_makes_each_named_root_zero
      (accepted.2.2.1 0 (by decide)) rootMember
  have source := fieldAt_refines_source hgv8rp03ProgramComponents.nonlinearExecutable
    publicWords (packedWitnessLaneRows packed 0) values
    hgv8rp03_nonlinear_expression_program_is_canonical evaluated entry.root
    (hgv8rp03_nonlinear_expression_program_is_canonical.2 _ rootMember)
  change fieldAt exactNonlinearExpressions _ _ entry.root = (values.getD entry.root 0 : F) at source
  have rootFieldZero : fieldAt exactNonlinearExpressions
      (fun n => (publicWords.getD n 0 : F))
      (fun n => ((packedWitnessLaneRows packed 0).getD n 0 : F)) entry.root = 0 := by
    rw [source]
    change (values[entry.root]?.getD 0 : F) = 0
    rw [rootZero]
    rfl
  rw [actual_asset_root_formula entry valid] at rootFieldZero
  have rowValue : (packedWitnessLaneRows packed 0).getD entry.row 0 =
      packedWord packed (densePrivateAddress entry.note + 64) := by
    simp [packedWitnessLaneRows, List.getD_eq_getElem?_getD, rowBound,
      Hegemon.Transaction.Poseidon2V8RelationProgram.relationRowCount,
      Hegemon.Transaction.Poseidon2V8RelationProgram.packingFactor, packedWord, address]
  simp only [active, Nat.cast_one, one_mul, rowValue] at rootFieldZero
  obtain ⟨slot, slotBound, nonpadding, equal⟩ := four_asset_factors_zero
    (candidates := fun slot => (publicWords.getD (54 + slot) 0 : F)) rootFieldZero
  refine ⟨slot, slotBound, ?_, ?_⟩
  · intro padding
    apply nonpadding
    exact congrArg (fun value : Nat => (value : F)) padding
  · exact canonical_nat_cast_injective
      (packed_word_canonical accepted.2.1 _)
      (V8Smz9ProgramPolynomials.canonical_getD publicWords accepted.1.2 _) equal

def assetRootAt (note : Nat) : AssetRoot := assetRoots.getD note default

theorem asset_root_at_valid {note : Nat} (bound : note < 4) :
    (assetRootAt note).Valid ∧ (assetRootAt note).note = note := by
  have cases : note = 0 ∨ note = 1 ∨ note = 2 ∨ note = 3 := by omega
  rcases cases with rfl | rfl | rfl | rfl <;>
    exact ⟨exact_asset_roots_valid _ (by simp [assetRootAt, assetRoots]), rfl⟩

theorem accepted_active_note_asset_member {publicWords packed : List Nat}
    (accepted : hgv8rp03ProgramComponents.AcceptsPacked publicWords packed)
    {note : Nat} (bound : note < 4) (active : publicWords.getD note 0 = 1) :
    ∃ slot, slot < 4 ∧ publicWords.getD (54 + slot) 0 ≠ balancePaddingAssetId ∧
      (projectNote packed (noteBridgeCall note)).assetId = publicWords.getD (54 + slot) 0 := by
  have entry := asset_root_at_valid bound
  have membership := accepted_active_asset_root_member accepted (assetRootAt note) entry.1
    (by simpa only [entry.2] using active)
  rw [entry.2] at membership
  obtain ⟨slot, slotBound, nonpadding, equal⟩ := membership
  refine ⟨slot, slotBound, nonpadding, ?_⟩
  change spongeSourceWord packed (noteBridgeCall note) 1 = _
  rw [accepted_note_source_bridge accepted bound (by decide)]
  exact equal

theorem flatten_length_uniform (width : Nat) : ∀ chunks : List (List Nat),
    (∀ chunk, chunk ∈ chunks → chunk.length = width) →
      chunks.flatten.length = chunks.length * width := by
  intro chunks
  induction chunks with
  | nil => simp
  | cons head tail ih =>
      intro lengths
      have headLength := lengths head (by simp)
      have tailLength := ih (by intro chunk member; exact lengths chunk (by simp [member]))
      simp [List.flatten_cons, headLength, tailLength, Nat.add_mul, Nat.add_comm]

theorem admitted_public_lengths (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement) :
    statement.inputFlags.length = 2 ∧ statement.outputFlags.length = 2 ∧
      statement.nullifiers.flatten.length = 14 ∧ statement.commitments.flatten.length = 14 ∧
      statement.ciphertextCommitments.flatten.length = 12 ∧ statement.merkleRoot.length = 7 ∧
      statement.balanceAssets.length = 4 := by
  obtain ⟨inputLength, outputLength, _, _, nullifierLength, nullifierWords,
    commitmentLength, commitmentWords, ciphertextLength, ciphertextWords,
    _, _, _, rootWords, assets, _⟩ := canonical
  have nullifierFlat := flatten_length_uniform 7 statement.nullifiers
    (by intro words member; exact (nullifierWords words member).1)
  have commitmentFlat := flatten_length_uniform 7 statement.commitments
    (by intro words member; exact (commitmentWords words member).1)
  have ciphertextFlat := flatten_length_uniform 6 statement.ciphertextCommitments
    (by intro words member; exact (ciphertextWords words member).1)
  refine ⟨inputLength, outputLength, ?_, ?_, ?_, rootWords.1, assets.1⟩
  · simpa only [nullifierLength, inputCount] using nullifierFlat
  · simpa only [commitmentLength, outputCount] using commitmentFlat
  · simpa only [ciphertextLength, outputCount] using ciphertextFlat

theorem encoded_input_flag (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    {input : Nat} (bound : input < 2) :
    (encodePublicStatement statement).getD input 0 = flagAt statement.inputFlags input := by
  have inputBound : input < statement.inputFlags.length := by
    rw [(admitted_public_lengths statement canonical).1]
    exact bound
  simp only [encodePublicStatement, List.append_assoc]
  rw [List.getD_append _ _ _ _ inputBound]
  rfl

theorem encoded_output_flag (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    {output : Nat} (bound : output < 2) :
    (encodePublicStatement statement).getD (2 + output) 0 = flagAt statement.outputFlags output := by
  have lengths := admitted_public_lengths statement canonical
  have outputBound : output < statement.outputFlags.length := by omega
  simp only [encodePublicStatement, List.append_assoc]
  rw [List.getD_append_right _ _ _ _ (by omega), lengths.1]
  simp only [Nat.add_sub_cancel_left]
  rw [List.getD_append _ _ _ _ outputBound]
  rfl

theorem encoded_balance_asset (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    {slot : Nat} (bound : slot < 4) :
    (encodePublicStatement statement).getD (54 + slot) 0 = wordAt statement.balanceAssets slot := by
  obtain ⟨inputLength, outputLength, nullifierLength, commitmentLength,
    ciphertextLength, rootLength, assetLength⟩ := admitted_public_lengths statement canonical
  let publicPrefix := statement.inputFlags ++ statement.outputFlags ++ statement.nullifiers.flatten ++
    statement.commitments.flatten ++ statement.ciphertextCommitments.flatten ++
    [statement.fee, statement.valueBalanceSign, statement.valueBalanceMagnitude] ++ statement.merkleRoot
  have prefixLength : publicPrefix.length = 54 := by
    simp [publicPrefix, inputLength, outputLength, nullifierLength, commitmentLength,
      ciphertextLength, rootLength]
  have encoded : encodePublicStatement statement = publicPrefix ++ (statement.balanceAssets ++
      (encodeCompatibility statement.compatibility ++ [statement.version, statement.cryptoSuite] ++
        encodeStablecoinPublic statement.stablecoin)) := by
    simp only [encodePublicStatement, publicPrefix, List.append_assoc]
  rw [encoded, List.getD_append_right _ _ _ _ (by omega), prefixLength]
  simp only [Nat.add_sub_cancel_left]
  rw [List.getD_append _ _ _ _ (by omega)]
  rfl

theorem admitted_input_flag_one (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    {input : Nat} (bound : input < 2) (active : flagAt statement.inputFlags input ≠ 0) :
    flagAt statement.inputFlags input = 1 := by
  have inputBound : input < statement.inputFlags.length := by
    rw [(admitted_public_lengths statement canonical).1]
    exact bound
  have member : flagAt statement.inputFlags input ∈ statement.inputFlags := by
    simp [flagAt, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem inputBound]
  rcases canonical.2.2.1 _ member with zero | one
  · exact False.elim (active zero)
  · exact one

theorem admitted_output_flag_one (statement : V8PublicStatement)
    (canonical : CanonicalPublicStatement exactV8SemanticPrimitives statement)
    {output : Nat} (bound : output < 2) (active : flagAt statement.outputFlags output ≠ 0) :
    flagAt statement.outputFlags output = 1 := by
  have outputBound : output < statement.outputFlags.length := by
    rw [(admitted_public_lengths statement canonical).2.1]
    exact bound
  have member : flagAt statement.outputFlags output ∈ statement.outputFlags := by
    simp [flagAt, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem outputBound]
  rcases canonical.2.2.2.1 _ member with zero | one
  · exact False.elim (active zero)
  · exact one

theorem admitted_active_note_asset_member {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {note : Nat} (noteBound : note < 4) (active : publicWords.getD note 0 = 1) :
    ∃ asset, asset ∈ statement.balanceAssets ∧
      asset = (projectNote packed (noteBridgeCall note)).assetId ∧ asset ≠ balancePaddingAssetId := by
  obtain ⟨slot, bound, nonpadding, equal⟩ :=
    accepted_active_note_asset_member domain.2.2 noteBound active
  have projection : publicWords.getD (54 + slot) 0 = wordAt statement.balanceAssets slot := by
    rw [← domain.1]
    exact encoded_balance_asset statement domain.2.1 bound
  rw [projection] at nonpadding equal
  have slotBound : slot < statement.balanceAssets.length := by
    rw [(admitted_public_lengths statement domain.2.1).2.2.2.2.2.2]
    exact bound
  refine ⟨wordAt statement.balanceAssets slot, ?_, equal.symm, nonpadding⟩
  simp [wordAt, List.getD_eq_getElem?_getD, List.getElem?_eq_getElem slotBound]

theorem admitted_input_asset_selectors {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {input : Nat} (bound : input < 2) (active : flagAt statement.inputFlags input ≠ 0) :
    (projectInput statement packed input).note.assetId ≠ balancePaddingAssetId ∧
      OneHotSelectorForAsset (projectInput statement packed input).active
        (projectInput statement packed input).note (projectInput statement packed input).balanceSelectors
        statement.balanceAssets := by
  have rawActive : publicWords.getD input 0 = 1 := by
    rw [← domain.1, encoded_input_flag statement domain.2.1 bound]
    exact admitted_input_flag_one statement domain.2.1 bound active
  have sourceMember := admitted_active_note_asset_member domain (by omega : input < 4) rawActive
  have member : ∃ asset, asset ∈ statement.balanceAssets ∧
      asset = (projectInput statement packed input).note.assetId ∧ asset ≠ balancePaddingAssetId := by
    have cases : input = 0 ∨ input = 1 := by omega
    rcases cases with rfl | rfl <;>
      simpa [projectInput, Hegemon.Transaction.Poseidon2V8DecoderRefinement.inputNoteCall,
        noteBridgeCall] using sourceMember
  constructor
  · obtain ⟨asset, _, equal, nonpadding⟩ := member
    intro padding
    exact nonpadding (equal.trans padding)
  · exact project_selectors_active_one_hot statement _ _
      (admitted_public_lengths statement domain.2.1).2.2.2.2.2.2 active member

theorem admitted_output_asset_selectors {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed)
    {output : Nat} (bound : output < 2) (active : flagAt statement.outputFlags output ≠ 0) :
    (projectOutput statement packed output).note.assetId ≠ balancePaddingAssetId ∧
      OneHotSelectorForAsset (projectOutput statement packed output).active
        (projectOutput statement packed output).note (projectOutput statement packed output).balanceSelectors
        statement.balanceAssets := by
  have rawActive : publicWords.getD (2 + output) 0 = 1 := by
    rw [← domain.1, encoded_output_flag statement domain.2.1 bound]
    exact admitted_output_flag_one statement domain.2.1 bound active
  have sourceMember := admitted_active_note_asset_member domain (by omega : 2 + output < 4) rawActive
  have member : ∃ asset, asset ∈ statement.balanceAssets ∧
      asset = (projectOutput statement packed output).note.assetId ∧ asset ≠ balancePaddingAssetId := by
    have cases : output = 0 ∨ output = 1 := by omega
    rcases cases with rfl | rfl <;>
      simpa [projectOutput, Hegemon.Transaction.Poseidon2V8DecoderRefinement.outputNoteCall,
        noteBridgeCall] using sourceMember
  constructor
  · obtain ⟨asset, _, equal, nonpadding⟩ := member
    intro padding
    exact nonpadding (equal.trans padding)
  · exact project_selectors_active_one_hot statement _ _
      (admitted_public_lengths statement domain.2.1).2.2.2.2.2.2 active member

theorem admitted_typed_witness_asset_selectors {statement : V8PublicStatement}
    {publicWords packed : List Nat}
    (domain : CanonicalPublicPackedDomain statement publicWords packed) :
    (∀ input, input < 2 → flagAt statement.inputFlags input ≠ 0 →
      let witness := (projectTypedWitness statement packed).inputs.getD input default
      witness.note.assetId ≠ balancePaddingAssetId ∧
        OneHotSelectorForAsset witness.active witness.note witness.balanceSelectors statement.balanceAssets) ∧
    (∀ output, output < 2 → flagAt statement.outputFlags output ≠ 0 →
      let witness := (projectTypedWitness statement packed).outputs.getD output default
      witness.note.assetId ≠ balancePaddingAssetId ∧
        OneHotSelectorForAsset witness.active witness.note witness.balanceSelectors statement.balanceAssets) := by
  constructor
  · intro input bound active
    simpa [projectTypedWitness, List.getD_eq_getElem?_getD, bound] using
      admitted_input_asset_selectors domain bound active
  · intro output bound active
    simpa [projectTypedWitness, List.getD_eq_getElem?_getD, bound] using
      admitted_output_asset_selectors domain bound active

end
end HegemonCrypto.SmallWood.V8Smz9SemanticAssetMembership
