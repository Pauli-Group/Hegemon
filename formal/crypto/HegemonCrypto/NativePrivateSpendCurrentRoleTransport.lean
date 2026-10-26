import HegemonCrypto.NativePrivateSpendCurrentProtocolHistory
import HegemonCrypto.NativePrivateSpendCurrentEvaluatorIdentity
import HegemonCrypto.NativePrivateSpendCurrentSpongeEvaluatorIdentity
import Mathlib.Algebra.BigOperators.Fin

/-! Exact source equations to fixed current primitive evaluators. The input
operation certificates contain no hash-output or history-success law. -/
set_option autoImplicit false
namespace HegemonCrypto.NativePrivateSpendCurrentRoleTransport
open NativePrivateSpendCurrentSixCaseSemantics NativePrivateSpendCurrentAcceptedHistory
open NativePrivateSpendCurrentProtocolHistory NativePrivateSpendCurrentEvaluatorIdentity
open NativePrivateSpendCurrentSpongeEvaluatorIdentity
open NativePrivateSpendRoleBridge NativePrivateSpendCurrentSourceCallContract
open NativePrivateSpendSpongeBridge NativePrivateSpendSymbolicBridge
open NativePrivateSpendSelectedNullifier NativePrivateSpendMerkleContinuation
open NativePrivateSpendArithmeticTopology NativePrivateSpendPackedLowering
open NativeLaunchConstraintAdapterBridge NativePrivateSpendLocalSemantics
open NativePrivateSpendCurrentRoleGames NativePrivateSpendCompffPrimitiveGames
open Hegemon.Transaction Hegemon.Transaction.Poseidon2V8SemanticSpecification
open HegemonCrypto.SmallWood.V8Smz9HonestHashMaterialization
open HegemonCrypto.SmallWood.V8Smz9TypedHashSchedule
noncomputable section
variable [Fact (Nat.Prime modulus)]
open scoped BigOperators

omit [Fact (Nat.Prime modulus)] in
theorem fixed_sponge_canonical (domain : Nat) (inputs : List Nat) :
    CanonicalWords (poseidon2V8Sponge domain inputs) := by
  have folded (blocks : List Nat) (state : List Nat) (canonical : CanonicalWords state)
      (total : Nat) : CanonicalWords
      (blocks.foldl (poseidon2V8AbsorbBlock domain inputs total) state) := by
    induction blocks generalizing state with
    | nil => exact canonical
    | cons block rest ih =>
      apply ih
      rw [sponge_absorb_is_source_preparation]
      exact permutation_words_canonical _
  have initial : CanonicalWords poseidon2V8InitialState := by
    intro value member
    have zero : value = 0 := (List.mem_replicate.mp member).2
    subst value
    exact modulus_positive
  unfold poseidon2V8Sponge
  intro value member
  apply folded _ poseidon2V8InitialState initial _ value
  exact List.mem_of_mem_take member

omit [Fact (Nat.Prime modulus)] in
theorem fixed_sponge_length (domain : Nat) (inputs : List Nat) :
    (poseidon2V8Sponge domain inputs).length = 7 := by
  have folded (blocks : List Nat) (state : List Nat) (shape : state.length = 16)
      (total : Nat) :
      (blocks.foldl (poseidon2V8AbsorbBlock domain inputs total) state).length = 16 := by
    induction blocks generalizing state with
    | nil => exact shape
    | cons block rest ih =>
      apply ih
      rw [sponge_absorb_is_source_preparation]
      exact permutation_shape _
  unfold poseidon2V8Sponge
  rw [List.length_take, folded _ poseidon2V8InitialState (by rfl) _]
  rfl

theorem source_sponge_coordinate (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (domain : K)
    (message : List (Word K)) (role : DigestWords)
    (checked : SpongeChecked g domain message role)
    (canonicalLength : message.length < modulus) (lane : Fin 7) :
    natural z (role lane) =
      (poseidon2V8Sponge domain.val (decoded z message)).getD lane.val 0 := by
  have equation := congrArg ZMod.val
    (source_sponge g layout z sem domain message role checked lane)
  change natural z (role lane) =
    (spongeNaturals z domain message).getD lane.val 0 % modulus at equation
  have takeRead : (spongeNaturals z domain message).getD lane.val 0 =
      ((spongeNaturals z domain message).take 7).getD lane.val 0 := by
    simp only [List.getD_eq_getElem?_getD, List.getElem?_take_of_lt lane.isLt]
  rw [takeRead, sponge_evaluator_exact z domain message canonicalLength] at equation
  change natural z (role lane) =
    (poseidon2V8Sponge domain.val (decoded z message)).getD lane.val 0 % modulus at equation
  have canonical : (poseidon2V8Sponge domain.val (decoded z message)).getD lane.val 0 < modulus :=
    getD_canonical _ (fixed_sponge_canonical domain.val (decoded z message)) lane.val
  exact equation.trans (Nat.mod_eq_of_lt canonical)

theorem source_sponge_digest (g : Graph K) (layout : Layout K) (z : Nat → K)
    (sem : StructuralSemantics g layout z) (domain : K)
    (message : List (Word K)) (role : DigestWords)
    (checked : SpongeChecked g domain message role)
    (canonicalLength : message.length < modulus) :
    digestNaturals z role = poseidon2V8Sponge domain.val (decoded z message) := by
  apply List.ext_getElem (by simp [digestNaturals, fixed_sponge_length])
  intro lane leftBound rightBound
  have bound : lane < 7 := by simpa [digestNaturals] using leftBound
  have coordinate := source_sponge_coordinate g layout z sem domain message role checked canonicalLength ⟨lane,bound⟩
  simpa only [digestNaturals, List.getElem_ofFn, List.getD_eq_getElem _ 0 rightBound,
    natural] using coordinate

theorem source_compression_coordinate (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z) (domain : K)
    (left right role : DigestWords) (checked : CompressChecked g domain left right role)
    (lane : Fin 7) :
    natural z (role lane) =
      (P.compress14 domain.val (digestNaturals z left) (digestNaturals z right)).getD lane.val 0 := by
  have equation := congrArg ZMod.val
    (source_compress g layout z sem domain left right role checked lane)
  rw [compression_frame_exact] at equation
  let raw := Poseidon2Width16Kernel.permutation
    (P.compressionFrame domain.val (digestNaturals z left) (digestNaturals z right))
  have canonical : raw.getD lane.val 0 < modulus :=
    getD_canonical _ (permutation_words_canonical _) lane.val
  rw [ZMod.val_add, ZMod.val_natCast] at equation
  change natural z (role lane) =
    (raw.getD lane.val 0 % modulus + (read z (left lane)).val) % modulus at equation
  rw [Nat.mod_eq_of_lt canonical, ← digestNaturals_getD z left lane.val lane.isLt] at equation
  have outputRead :
      (P.compress14 domain.val (digestNaturals z left) (digestNaturals z right)).getD lane.val 0 =
        (raw.getD lane.val 0 + (digestNaturals z left).getD lane.val 0) % modulus := by
    simp only [P.compress14, Hegemon.Transaction.Poseidon2V8SemanticSpecification.digestWords,
      List.getD_eq_getElem?_getD, List.getElem?_map,
      List.getElem?_range lane.isLt, Option.map_some, Option.getD_some]
    rfl
  exact equation.trans outputRead.symm

theorem source_compression_digest (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z) (domain : K)
    (left right role : DigestWords) (checked : CompressChecked g domain left right role) :
    digestNaturals z role = P.compress14 domain.val
      (digestNaturals z left) (digestNaturals z right) := by
  apply List.ext_getElem (by simp [digestNaturals,
    Hegemon.Transaction.Poseidon2V8LeftFeedForwardPrimitives.compressed_digest_has_seven_lanes])
  intro lane leftBound rightBound
  have bound : lane < 7 := by simpa [digestNaturals] using leftBound
  have coordinate := source_compression_coordinate g layout z sem domain left right role checked ⟨lane,bound⟩
  rw [List.getElem_eq_getD 0, List.getElem_eq_getD 0]
  exact (digestNaturals_getD z role lane bound).trans coordinate

def sourceContext (z : Nat → K) (r : Roles) : Context where
  key := fun i => canonicalWord z (r.treasuryKey i)
  tags := fun i lane => canonicalWord z (r.tags ⟨7*i.val+lane.val,by omega⟩)
  intent := fun i => canonicalWord z (r.intent i)

theorem source_policy_message (z : Nat → K) (r : Roles) :
    decoded z (NativePrivateSpendRoleBridge.policyMessage r) =
      NativePrivateSpendCurrentRoleGames.policyMessage (sourceContext z r).tags := by
  have tagWords : (List.ofFn fun i : Fin 21 => natural z (r.tags i)) =
      (List.ofFn fun i : Fin 3 => canonicalDigestWords ((sourceContext z r).tags i)).flatten := by
    rw [List.ofFn_mul (m := 3) (n := 7)]
    apply congrArg List.flatten
    apply congrArg List.ofFn
    funext i
    apply congrArg List.ofFn
    funext lane
    simp [sourceContext, canonicalWord, natural, Nat.mul_comm]
  have twoVal : (2 : K).val = 2 := ZMod.val_ofNat_of_lt (by decide : 2 < modulus)
  have threeVal : (3 : K).val = 3 := ZMod.val_ofNat_of_lt (by decide : 3 < modulus)
  simp only [decoded, NativePrivateSpendRoleBridge.policyMessage,
    List.map_append, List.map_cons, List.map_nil, List.map_ofFn, List.map_replicate,
    NativeLaunchConstraintAdapterBridge.read]
  change [(2 : K).val, (3 : K).val] ++
    (List.ofFn fun i : Fin 21 => natural z (r.tags i)) ++ List.replicate 21 (0 : K).val = _
  rw [twoVal, threeVal, ZMod.val_zero]
  exact congrArg (fun xs : List Nat => [2,3] ++ xs ++ List.replicate 21 0) tagWords

omit [Fact (Nat.Prime modulus)] in
theorem source_intent_message (z : Nat → K) (r : Roles) :
    decoded z (List.ofFn r.intent) = words (sourceContext z r).intent := by
  simp only [decoded, NativePrivateSpendCurrentRoleGames.words, List.map_ofFn]
  rfl

theorem source_padded_key (z : Nat → K) (key : Fin 5 → Word K) :
    digestNaturals z (paddedKey key) =
      canonicalSingleKeyWords (fun i => canonicalWord z (key i)) := by
  rw [digestNaturals, List.ofFn_add (n := 5) (m := 2), canonicalSingleKeyWords]
  apply congrArg₂ List.append
  · apply congrArg List.ofFn
    funext i
    change (read z (if h : i.val < 5 then key ⟨i.val,h⟩ else .constant 0)).val =
      (read z (key i)).val
    rw [dif_pos i.isLt]
  · have zeros : (fun i : Fin 2 =>
        (read z (paddedKey key (i.natAdd 5))).val) = (fun _ : Fin 2 => 0) := by
      funext i
      change (read z (if h : 5+i.val < 5 then key ⟨5+i.val,h⟩ else .constant 0)).val = 0
      rw [dif_neg (by omega)]
      rfl
    rw [zeros]
    rfl

theorem source_bits_message (z : Nat → K) (bits : Bits3)
    (boolean : ∀ i, read z (bits i) = 0 ∨ read z (bits i) = 1) :
    decoded z (List.ofFn bits) = approvalWords (bitmapBits (sourceBitmap z bits)) := by
  classical
  simp only [decoded, List.map_ofFn, approvalWords]
  apply congrArg List.ofFn
  funext i
  have oneVal : (1 : K).val = 1 :=
    (ZMod.val_one_eq_one_mod modulus).trans (Nat.mod_eq_of_lt (by decide))
  rcases boolean i with zero | one
  · simp [bitmapBits, sourceBitmap, zero]
  · simp [bitmapBits, sourceBitmap, one, oneVal]

omit [Fact (Nat.Prime modulus)] in
theorem bitmap_approval_count (bitmap : Finset Slot) :
    approvalCount (bitmapBits bitmap) = bitmap.card := by
  classical
  have laneValue (i : Slot) :
      (bitmapBits bitmap i).val = if i ∈ bitmap then 1 else 0 := by
    by_cases member : i ∈ bitmap
    · simp only [bitmapBits, if_pos member]
      rfl
    · simp only [bitmapBits, if_neg member]
      rfl
  unfold approvalCount approvalWords
  rw [Fin.sum_ofFn]
  simp only [laneValue]
  exact (Finset.card_eq_sum_ite (show bitmap ⊆ Finset.univ from Finset.subset_univ _)).symm

theorem source_policy_digest (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (r : Roles) (calls : CallsChecked g r) :
    digestNaturals z r.policyRoot = policyDigest (sourceContext z r).tags := by
  have equation := source_sponge_digest g layout z sem _ _ _ calls.policy
    (by simp [NativePrivateSpendRoleBridge.policyMessage]; norm_num [modulus])
  rw [source_policy_message] at equation
  have domain : NativePrivateSpendRoleBridge.policyDomain.val =
      NativePrivateSpendCurrentRoleGames.policyDomain := by
    change (0x48415038504f4c01 : ZMod modulus).val = 0x48415038504f4c01
    exact ZMod.val_ofNat_of_lt (by decide : 0x48415038504f4c01 < modulus)
  simpa only [policyDigest, domain] using equation

theorem source_intent_digest (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (r : Roles) (calls : CallsChecked g r) :
    digestNaturals z r.intentDigest =
      poseidon2V8Sponge NativePrivateSpendCurrentRoleGames.intentDomain
        (words (sourceContext z r).intent) := by
  have equation := source_sponge_digest g layout z sem _ _ _ calls.intent
    (by simp; norm_num [modulus])
  rw [source_intent_message] at equation
  have domain : NativePrivateSpendRoleBridge.intentDomain.val =
      NativePrivateSpendCurrentRoleGames.intentDomain := by
    change (0x5053494e544e0001 : ZMod modulus).val = 0x5053494e544e0001
    exact ZMod.val_ofNat_of_lt (by decide : 0x5053494e544e0001 < modulus)
  simpa only [domain] using equation

theorem source_accumulator_message (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (r : Roles) (calls : CallsChecked g r)
    (bits : Bits3) (count : Word K)
    (boolean : ∀ i, read z (bits i) = 0 ∨ read z (bits i) = 1)
    (checkedSum : ThreeSumChecked g bits count) :
    decoded z (NativePrivateSpendRoleBridge.accumulatorMessage r bits count) =
      NativePrivateSpendCurrentRoleGames.accumulatorMessage
        (accumulatorInput (sourceContext z r) (sourceBitmap z bits)) := by
  have bitWords := source_bits_message z bits boolean
  have countEq := bitmap_count_from_equations z bits count boolean
    (three_sum_sound g layout z sem bits count checkedSum)
  have countRead : (read z count).val = approvalCount (bitmapBits (sourceBitmap z bits)) :=
    countEq.trans (bitmap_approval_count _).symm
  simp only [decoded, NativePrivateSpendRoleBridge.accumulatorMessage,
    NativePrivateSpendCurrentRoleGames.accumulatorMessage, accumulatorInput,
    List.map_append, List.map_cons, List.map_nil, List.map_replicate,
    List.map_ofFn]
  change digestNaturals z r.policyRoot ++ digestNaturals z r.intentDigest ++
    [((2 : K).val), ((3 : K).val), (read z count).val] ++
    decoded z (List.ofFn bits) ++ List.replicate 3 ((0 : K).val) = _
  rw [source_policy_digest g layout z sem r calls,
    source_intent_digest g layout z sem r calls, countRead, bitWords]
  have twoVal : (2 : K).val = 2 := ZMod.val_ofNat_of_lt (by decide : 2 < modulus)
  have threeVal : (3 : K).val = 3 := ZMod.val_ofNat_of_lt (by decide : 3 < modulus)
  rw [twoVal, threeVal, ZMod.val_zero]

/-- Both before and next accumulator callers can use this one theorem. The
bitmap/count and every intermediate digest are from the same source values. -/
theorem source_accumulator_owner (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (r : Roles) (calls : CallsChecked g r) (bits : Bits3) (count : Word K)
    (inner owner : DigestWords)
    (boolean : ∀ i, read z (bits i) = 0 ∨ read z (bits i) = 1)
    (checkedSum : ThreeSumChecked g bits count)
    (sponge : SpongeChecked g NativePrivateSpendRoleBridge.accumulatorDomain
      (NativePrivateSpendRoleBridge.accumulatorMessage r bits count) inner)
    (compress : CompressChecked g NativePrivateSpendRoleBridge.bindDomain
      (paddedKey r.treasuryKey) inner owner) :
    digestNaturals z owner = encodedAccumulator (sourceContext z r) (sourceBitmap z bits) := by
  have innerEq := source_sponge_digest g layout z sem _ _ _ sponge
    (by simp [NativePrivateSpendRoleBridge.accumulatorMessage]; norm_num [modulus])
  rw [source_accumulator_message g layout z sem r calls bits count boolean checkedSum] at innerEq
  have outerEq := source_compression_digest g layout z sem _ _ _ _ compress
  rw [source_padded_key, innerEq] at outerEq
  have innerDomain : NativePrivateSpendRoleBridge.accumulatorDomain.val =
      NativePrivateSpendCurrentRoleGames.accumulatorDomain := by
    change (0x5053414343550001 : ZMod modulus).val = 0x5053414343550001
    exact ZMod.val_ofNat_of_lt (by decide : 0x5053414343550001 < modulus)
  have outerDomain : NativePrivateSpendRoleBridge.bindDomain.val =
      HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry.currentAuthorizationBindingDomain := by
    change (0x484d424456320001 : ZMod modulus).val = 0x484d424456320001
    exact ZMod.val_ofNat_of_lt (by decide : 0x484d424456320001 < modulus)
  simpa only [encodedAccumulator, accumulatorOwner, accumulatorInput, sourceContext,
    innerDomain, outerDomain] using outerEq

def outputOwnerWords (output : Fin 18 → Word K) : DigestWords := fun i =>
  output ⟨if i.val < 4 then 14+i.val else 6+i.val,by
    have bound := i.isLt
    split_ifs <;> omega⟩

/-- Equalities concern Word/address data only, independent of assignments. -/
structure RecordRouteBinding (v : RouteRoles) (w : Nat → Word K)
    (output : Fin 18 → Word K) where
  inputOwner : v.input0Owner = owner w (0 : Fin 2)
  occupied : v.occupied0 = NativePrivateSpendSelectedNullifier.occupied w (0 : Fin 2)
  outputOwner : v.output0Owner = outputOwnerWords output

/-- The actual output wrapper, on its unrestricted seven-word recipient. -/
structure OrdinaryOutputChecked (g : Graph K) (recipient owner : DigestWords) where
  call : SpongeChecked g (NativePrivateSpendCurrentRoleGames.ordinaryOwnerDomain : K)
    (List.ofFn recipient) owner

theorem source_ordinary_output (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (recipient owner : DigestWords) (checked : OrdinaryOutputChecked g recipient owner) :
    digestNaturals z owner = ordinaryRecipientOwner (digestNaturals z recipient) := by
  have equation := source_sponge_digest g layout z sem _ _ _ checked.call
    (by simp; norm_num [modulus])
  have domain : (NativePrivateSpendCurrentRoleGames.ordinaryOwnerDomain : K).val =
      NativePrivateSpendCurrentRoleGames.ordinaryOwnerDomain := by
    exact ZMod.val_natCast_of_lt
      (by decide : NativePrivateSpendCurrentRoleGames.ordinaryOwnerDomain < modulus)
  have message : decoded z (List.ofFn recipient) = digestNaturals z recipient := by
    simp only [decoded, List.map_ofFn, digestNaturals, Function.comp_def]
  rw [message, domain] at equation
  exact equation

theorem approval_next_boolean (z : Nat → K) (r : Roles)
    (inputValue outputValue : Word K)
    (consequences : ApprovalConsequences z r inputValue outputValue) :
    ∀ i, read z (r.next i) = 0 ∨ read z (r.next i) = 1 := by
  intro i
  have equation := consequences.next i
  have disjoint := consequences.disjoint i
  rcases consequences.beforeBits i with before | before
  <;> rcases consequences.signerBits i with signer | signer
  <;> simp_all

/-- All advance checks except the actual historical parent identity are now
derived on the exact projected source record. Nothing supplied is an
authorized-owner or successful replay assertion. -/
theorem relation_record_credentials_and_owner (relation : Current.Relation)
    (packed : Current.Values) (valid : Current.Satisfies relation packed)
    (g : Graph K) (layout : Layout K) (csr : NativePrivateSpendCsrCertificate.RawCSR K)
    (certificate : RelationCertificate relation g layout csr)
    (stage outputPosition : Nat) (r : Roles) (v : RouteRoles)
    (w : Nat → Word K) (output : Fin 18 → Word K)
    (calls : CallsChecked g r) (routes : RouteChecked g r v)
    (recordBinding : RecordRouteBinding v w output)
    (approval : ApprovalChecked g r v (noteWords w (0 : Fin 2) 0) (output 0))
    (signer : ApprovalSignerChecked g r v w)
    (selected : natural (sourceAssignment packed) (v.modes 1) = 1) :
    let record := recordFromSource stage outputPosition packed r v w signer.who output
    singleKeyEvaluator record.signerKey = record.signerAuthority ∧
      record.signerAuthority = canonicalDigestWords (record.context.tags record.signer) ∧
      record.afterOwner = encodedAccumulator record.context record.after := by
  let z := sourceAssignment packed
  let record := recordFromSource stage outputPosition packed r v w signer.who output
  have sem := relation_derives_structural_semantics relation packed valid g layout csr certificate
  have arithmetic := approval_consequences g layout z sem r v _ _ approval selected
  have signerOne : read z (r.signer (sourceSigner z r.signer)) = 1 :=
    (sourceSigner_unique z r _ _ arithmetic _).mpr rfl
  have policy := (approval_selected_signer g layout z sem r v w signer selected
    (sourceSigner z r.signer) signerOne).2
  have single := source_sponge_digest g layout z sem _ _ _ signer.single
    (by simp; norm_num [modulus])
  have singleMessage : decoded z
      (List.ofFn (NativePrivateSpendSelectedNullifier.key w (1 : Fin 2)) ++ [.constant 0,.constant 0]) =
      canonicalSingleKeyWords record.signerKey := by
    simp only [decoded, List.map_append, List.map_ofFn, List.map_cons, List.map_nil,
      canonicalSingleKeyWords]
    rfl
  rw [singleMessage] at single
  have singleDomain : (0x48534b4156320001 : K).val =
      HegemonCrypto.SmallWood.SmzaRp05ThresholdRegistry.currentSourceSingleKeyDomain := by
    change (0x48534b4156320001 : ZMod modulus).val = 0x48534b4156320001
    exact ZMod.val_ofNat_of_lt (by decide : 0x48534b4156320001 < modulus)
  have credential : singleKeyEvaluator record.signerKey = record.signerAuthority := by
    simpa only [singleKeyEvaluator, singleDomain, record, recordFromSource,
      digestNaturals, natural] using single.symm
  have membership : record.signerAuthority =
      canonicalDigestWords (record.context.tags record.signer) := by
    apply congrArg List.ofFn
    funext lane
    exact congrArg ZMod.val (policy lane)
  have accumulator := source_accumulator_owner g layout z sem r calls r.next r.nextCount
    r.nextAccumulatorInner r.nextAccumulator (approval_next_boolean z r _ _ arithmetic)
    calls.nextCount calls.nextAccumulatorInner calls.nextAccumulator
  have outputEq : digestNaturals z v.output0Owner = digestNaturals z r.nextAccumulator := by
    apply congrArg List.ofFn
    funext lane
    exact congrArg ZMod.val
      (NativePrivateSpendHtlcRecipient.selected_gate g layout z sem _ _ _
        (routes.approvalOutput lane) selected)
  rw [recordBinding.outputOwner, accumulator] at outputEq
  exact ⟨credential, membership, outputEq⟩

theorem relation_record_advance_checks (relation : Current.Relation)
    (packed : Current.Values) (valid : Current.Satisfies relation packed)
    (g : Graph K) (layout : Layout K) (csr : NativePrivateSpendCsrCertificate.RawCSR K)
    (certificate : RelationCertificate relation g layout csr)
    (stage outputPosition : Nat) (r : Roles) (v : RouteRoles)
    (w : Nat → Word K) (output : Fin 18 → Word K)
    (calls : CallsChecked g r) (routes : RouteChecked g r v)
    (recordBinding : RecordRouteBinding v w output)
    (approval : ApprovalChecked g r v (noteWords w (0 : Fin 2) 0) (output 0))
    (signer : ApprovalSignerChecked g r v w)
    (selected : natural (sourceAssignment packed) (v.modes 1) = 1) :
    let record := recordFromSource stage outputPosition packed r v w signer.who output
    record.after = insert record.signer record.before ∧ record.signer ∉ record.before ∧
      record.beforeValue = 0 ∧ record.afterValue = 0 ∧
      singleKeyEvaluator record.signerKey = record.signerAuthority ∧
      record.signerAuthority = canonicalDigestWords (record.context.tags record.signer) ∧
      record.afterOwner = encodedAccumulator record.context record.after := by
  have arithmetic := relation_record_approval_checks relation packed valid g layout csr certificate
    stage outputPosition r v w signer.who output approval selected
  have hashes := relation_record_credentials_and_owner relation packed valid g layout csr certificate
    stage outputPosition r v w output calls routes recordBinding approval signer selected
  exact ⟨arithmetic.2.1, arithmetic.1, arithmetic.2.2.1, arithmetic.2.2.2,
    hashes.1, hashes.2.1, hashes.2.2⟩

/-- The extra source operations are precisely the absent-parent count gate
and occupied-parent nonzero gate in circuit.rs. No origin conclusion occurs
in this data certificate. -/
structure ApprovalParentChecked (g : Graph K) (r : Roles) (v : RouteRoles) where
  occupiedBit : BooleanData g v.occupied0
  vacancy : Word K
  firstApproval : Word K
  vacancySub : SubData g (.constant 1) v.occupied0 vacancy
  firstMul : MulData g (v.modes 1) vacancy firstApproval
  firstCount : GateData g firstApproval r.count (.constant 0)
  countInverse : Word K
  countProduct : Word K
  countMul : MulData g r.count countInverse countProduct
  occupiedCount : GateData g v.approvalOccupied countProduct (.constant 1)

theorem approval_occupied_selector (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (r : Roles) (v : RouteRoles) (routes : RouteChecked g r v)
    (selected : natural z (v.modes 1) = 1) (occupied : read z v.occupied0 = 1) :
    natural z v.approvalOccupied = 1 := by
  have mode : read z (v.modes 1) = 1 := by
    rw [← natural_cast z (v.modes 1), selected, Nat.cast_one]
  have product := mul_sound g layout z sem routes.approvalActive
  rw [mode, occupied, one_mul] at product
  simpa only [natural, ZMod.val_one] using congrArg ZMod.val product

/-- In the absent-parent branch the source bitmap is empty. In the occupied
branch the SAME source count is nonzero; value zero does not select this
absent-parent branch. -/
theorem approval_parent_bitmap (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (r : Roles) (v : RouteRoles) (calls : CallsChecked g r)
    (routes : RouteChecked g r v) (checked : ApprovalParentChecked g r v)
    (bits : ∀ i, BooleanData g (r.approved i))
    (selected : natural z (v.modes 1) = 1) :
    (read z v.occupied0 = 0 → sourceBitmap z r.approved = ∅) ∧
    (read z v.occupied0 = 1 → (sourceBitmap z r.approved).Nonempty) := by
  have count := source_bitmap_count g layout z sem _ _ bits calls.count
  constructor
  · intro emptyInput
    have mode : read z (v.modes 1) = 1 := by
      rw [← natural_cast z (v.modes 1), selected, Nat.cast_one]
    have vacancy := sub_sound g layout z sem checked.vacancySub
    have first := mul_sound g layout z sem checked.firstMul
    change read z checked.vacancy = 1 - read z v.occupied0 at vacancy
    rw [emptyInput, sub_zero] at vacancy
    rw [mode, vacancy, one_mul] at first
    have firstNat : natural z checked.firstApproval = 1 := by
      simpa only [natural, ZMod.val_one] using congrArg ZMod.val first
    have zero := NativePrivateSpendHtlcRecipient.selected_gate g layout z sem _ _ _
      checked.firstCount firstNat
    have countZero : natural z r.count = 0 := by
      simpa only [natural, NativeLaunchConstraintAdapterBridge.read, ZMod.val_zero]
        using congrArg ZMod.val zero
    exact Finset.card_eq_zero.mp (count.symm.trans countZero)
  · intro occupiedInput
    have active := approval_occupied_selector g layout z sem r v routes selected occupiedInput
    have nonzero := NativePrivateSpendHtlcRecipient.selected_gate g layout z sem _ _ _
      checked.occupiedCount active
    rw [mul_sound g layout z sem checked.countMul] at nonzero
    have countNonzero : read z r.count ≠ 0 := by
      intro zero
      rw [zero, zero_mul] at nonzero
      exact zero_ne_one nonzero
    apply Finset.card_pos.mp
    by_contra noPositive
    have cardZero : (sourceBitmap z r.approved).card = 0 := by omega
    have naturalZero := count.trans cardZero
    exact countNonzero (by rw [← natural_cast z r.count, naturalZero, Nat.cast_zero])

/-- Actual occupied source owner, including zero-valued notes. This theorem
does not yet identify a historical producer: it proves the consumer's fixed
owner expression, which is then compared to that producer. -/
theorem source_occupied_approval_owner (g : Graph K) (layout : Layout K)
    (z : Nat → K) (sem : StructuralSemantics g layout z)
    (r : Roles) (v : RouteRoles) (calls : CallsChecked g r)
    (routes : RouteChecked g r v)
    (bits : ∀ i, BooleanData g (r.approved i))
    (selected : natural z (v.modes 1) = 1) (occupied : read z v.occupied0 = 1) :
    digestNaturals z v.input0Owner =
      encodedAccumulator (sourceContext z r) (sourceBitmap z r.approved) := by
  have active := approval_occupied_selector g layout z sem r v routes selected occupied
  have owner := source_accumulator_owner g layout z sem r calls r.approved r.count
    r.accumulatorInner r.accumulator
    (fun i => boolean_sound g layout z sem _ (bits i))
    calls.count calls.accumulatorInner calls.accumulator
  have equalOwner : digestNaturals z v.input0Owner = digestNaturals z r.accumulator := by
    apply congrArg List.ofFn
    funext lane
    exact congrArg ZMod.val
      (NativePrivateSpendHtlcRecipient.selected_gate g layout z sem _ _ _
        (routes.approvalInput lane) active)
  exact equalOwner.trans owner
end
end HegemonCrypto.NativePrivateSpendCurrentRoleTransport
