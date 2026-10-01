import SmzaRp05CsrNormalization
import SmzaRp05ThresholdRegistry
import HegemonCrypto.Poseidon2V8ExpressionRootSemantics

/-!
# Current RP05 packed-program to typed local relation

This file does not use the RP04 fixed-program implication.  It gives a small
syntactic certificate format for the current 818-root executable DAG and
derives its local AUTH equations from `AcceptsPacked`.  A certificate proves
only finite node lookups, root membership, and CSR-attempt membership; it has
no field accepting an arbitrary witness-to-semantics implication.
-/

namespace HegemonCrypto.SmallWood.SmzaRp05TypedRelation

open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9ProgramPolynomials
open HegemonCrypto.SmallWood.Poseidon2V8ExpressionRootSemantics
open SmzaRp05RelationRefinement
open SmzaRp05ThresholdHistory
open SmzaRp05ThresholdRegistry

set_option autoImplicit false
open scoped Classical

/-! ## A syntax-directed certificate, not a semantic certificate -/

inductive SourceTerm where
  | constant (value : Nat)
  | publicInput (index : Nat)
  | witness (row : Nat)
  | add (left right : SourceTerm)
  | sub (left right : SourceTerm)
  | mul (left right : SourceTerm)
deriving DecidableEq

def SourceTerm.eval (publicWords rows : Nat → Goldilocks) : SourceTerm → Goldilocks
  | .constant value => value
  | .publicInput index => publicWords index
  | .witness row => rows row
  | .add left right => left.eval publicWords rows + right.eval publicWords rows
  | .sub left right => left.eval publicWords rows - right.eval publicWords rows
  | .mul left right => left.eval publicWords rows * right.eval publicWords rows

/-- `Realizes expressions root term` is entirely syntactic.  Generated proof
terms consist only of `List.getElem?` equalities and child-index bounds. -/
inductive Realizes (expressions : List FieldExpression) : Nat → SourceTerm → Prop where
  | constant {node value} (found : expressions[node]? = some (.constant value)) :
      Realizes expressions node (.constant value)
  | publicInput {node index} (found : expressions[node]? = some (.publicWord index)) :
      Realizes expressions node (.publicInput index)
  | witness {node row} (found : expressions[node]? = some (.witnessRow row)) :
      Realizes expressions node (.witness row)
  | add {node leftNode rightNode left right}
      (found : expressions[node]? = some (.add leftNode rightNode))
      (leftEarlier : leftNode < node) (rightEarlier : rightNode < node)
      (leftRealizes : Realizes expressions leftNode left)
      (rightRealizes : Realizes expressions rightNode right) :
      Realizes expressions node (.add left right)
  | sub {node leftNode rightNode left right}
      (found : expressions[node]? = some (.sub leftNode rightNode))
      (leftEarlier : leftNode < node) (rightEarlier : rightNode < node)
      (leftRealizes : Realizes expressions leftNode left)
      (rightRealizes : Realizes expressions rightNode right) :
      Realizes expressions node (.sub left right)
  | mul {node leftNode rightNode left right}
      (found : expressions[node]? = some (.mul leftNode rightNode))
      (leftEarlier : leftNode < node) (rightEarlier : rightNode < node)
      (leftRealizes : Realizes expressions leftNode left)
      (rightRealizes : Realizes expressions rightNode right) :
      Realizes expressions node (.mul left right)

theorem fieldAt_of_realizes {expressions : List FieldExpression}
    {node : Nat} {term : SourceTerm} (realizes : Realizes expressions node term)
    (publicWords rows : Nat → Goldilocks) :
    fieldAt expressions publicWords rows node = term.eval publicWords rows := by
  induction realizes with
  | constant found =>
      rw [fieldAt_eq, found]
      simp [SourceTerm.eval, expressionField]
  | publicInput found =>
      rw [fieldAt_eq, found]
      simp [SourceTerm.eval, expressionField]
  | witness found =>
      rw [fieldAt_eq, found]
      simp [SourceTerm.eval, expressionField]
  | add found leftEarlier rightEarlier _ _ leftInduction rightInduction =>
      rw [fieldAt_eq, found]
      simp [SourceTerm.eval, expressionField, leftEarlier, rightEarlier,
        leftInduction, rightInduction]
  | sub found leftEarlier rightEarlier _ _ leftInduction rightInduction =>
      rw [fieldAt_eq, found]
      simp [SourceTerm.eval, expressionField, leftEarlier, rightEarlier,
        leftInduction, rightInduction]
  | mul found leftEarlier rightEarlier _ _ leftInduction rightInduction =>
      rw [fieldAt_eq, found]
      simp [SourceTerm.eval, expressionField, leftEarlier, rightEarlier,
        leftInduction, rightInduction]

/-! ## Current RP05 local AUTH formula inventory -/

abbrev tconst (value : Nat) := SourceTerm.constant value
abbrev tpub (index : Nat) := SourceTerm.publicInput index
abbrev trow (row : Nat) := SourceTerm.witness row
abbrev tadd := SourceTerm.add
abbrev tsub := SourceTerm.sub
abbrev tmul := SourceTerm.mul

def productTerms : List SourceTerm → SourceTerm
  | [] => tconst 1
  | head :: tail => tail.foldl tmul head

def sumTerms (terms : List SourceTerm) : SourceTerm :=
  terms.foldl tadd (tconst 0)

def phiTerm (gate value : SourceTerm) : SourceTerm :=
  tadd (tsub (tconst 1) gate) (tmul value gate)

/-- Exact current source rows (`AUTH_ROW_START=92`, 139 used of 155). -/
def singleRow : Nat := 92
def approvalRow : Nat := 93
def finalRow : Nat := 94
def modeRow (mode : Fin 3) : Nat := 92 + mode.val
def legacyTagRow (limb : Fin 7) : Nat := 99 + limb.val
def inputNoteVectorRow (input : Fin 2) : Nat := 95 + input.val
def legacyVectorRow : Nat := 106
def nextVectorRow : Nat := 107
def valueLockVectorRow : Nat := 108
def secondaryInputVectorRow : Nat := 109
def boundCurrentVectorRow : Nat := 110
def boundSecondaryVectorRow : Nat := 111
def outputZeroVectorRow : Nat := 112
def countRow : Nat := 138
def nextCountRow : Nat := 145
def approvedRow (slot : SignerSlot) : Nat := 139 + slot.val
def nextApprovedRow (slot : SignerSlot) : Nat := 146 + slot.val
def signerFlagRow (slot : SignerSlot) : Nat := 153 + slot.val
def policyTagRow (slot : SignerSlot) (limb : Fin 7) : Nat :=
  164 + 7 * slot.val + limb.val
def membershipRow (slot : SignerSlot) : Nat := 206 + slot.val
def inputValueRow (input : Fin 2) : Nat := 34 * input.val
def inputAssetRow (input : Fin 2) : Nat := 1 + 34 * input.val
def outputValueRow (output : Fin 2) : Nat := 68 + 12 * output.val
def outputAssetRow (output : Fin 2) : Nat := 69 + 12 * output.val
def inputInverseRow : Nat := 229
def outputInverseRow : Nat := 230

inductive LocalCheck where
  | activityBoolean (index : Fin 4)
  | modeBoolean (mode : Fin 3)
  | modeOneHot
  | t1 | t2 | t4 | t5
  | t3 (index : Fin 6)
  | approvalInputOne | approvalOutputZero
  | nextCount
  | membershipBoolean (slot : SignerSlot)
  | membershipOneHot
  | membershipFresh (slot : SignerSlot)
  | nextBitmap (slot : SignerSlot)
  | fullTag (slot : SignerSlot) (limb : Fin 7)
  | policyDigestBridge (limb : Fin 7)
  | inputAuthorization (input : Fin 2)
  | finalIntent (limb : Fin 7)
  | outputAuthorization
  | secondaryInput
deriving DecidableEq

def t1Term : SourceTerm :=
  let ordinary0 := tmul (tpub 0) (tadd (trow singleRow) (trow finalRow))
  let ordinary1 := tmul (tpub 1) (tadd (trow singleRow) (trow approvalRow))
  tsub (tmul (trow inputInverseRow)
    (tmul (phiTerm ordinary0 (trow (inputValueRow 0)))
      (phiTerm ordinary1 (trow (inputValueRow 1))))) (tconst 1)

def t2Term : SourceTerm :=
  let ordinary0 := tmul (tpub 2) (tadd (trow singleRow) (trow finalRow))
  tsub (tmul (trow outputInverseRow)
    (tmul (phiTerm ordinary0 (trow (outputValueRow 0)))
      (tadd (tsub (tconst 1) (tpub 3))
        (tmul (tpub 3) (trow (outputValueRow 1)))))) (tconst 1)

def t3Term (index : Fin 6) : SourceTerm :=
  ([tmul (trow (inputValueRow 0)) (trow approvalRow),
    tmul (trow (inputAssetRow 0)) (trow approvalRow),
    tmul (trow (outputValueRow 0)) (trow approvalRow),
    tmul (trow (outputAssetRow 0)) (trow approvalRow),
    tmul (trow (inputValueRow 1)) (trow finalRow),
    tmul (trow (inputAssetRow 1)) (trow finalRow)] : List SourceTerm).get index

def localCheckTerm : LocalCheck → SourceTerm
  | .activityBoolean index => tmul (tpub index.val)
      (tsub (tpub index.val) (tconst 1))
  | .modeBoolean mode => tmul (trow (modeRow mode))
      (tsub (trow (modeRow mode)) (tconst 1))
  | .modeOneHot => tsub
      (tadd (trow finalRow) (tadd (trow singleRow) (trow approvalRow)))
      (tconst 1)
  | .t1 => t1Term
  | .t2 => t2Term
  | .t3 index => t3Term index
  | .t4 => tmul (trow countRow)
      (tmul (trow approvalRow) (tsub (tconst 1) (tpub 0)))
  | .t5 => tmul (tmul (tpub 0) (trow approvalRow))
      (productTerms ((List.range 6).map fun offset =>
        tsub (trow countRow) (tconst (offset + 1))))
  | .approvalInputOne => tmul (trow approvalRow) (tsub (tpub 1) (tconst 1))
  | .approvalOutputZero => tmul (trow approvalRow) (tsub (tpub 2) (tconst 1))
  | .nextCount => tmul (trow approvalRow)
      (tsub (tsub (trow nextCountRow) (trow countRow)) (tconst 1))
  | .membershipBoolean slot => tmul (trow approvalRow)
      (tmul (trow (membershipRow slot))
        (tsub (trow (membershipRow slot)) (tconst 1)))
  | .membershipOneHot => tmul (trow approvalRow)
      (tsub (tadd (trow (membershipRow 5))
        (tadd (trow (membershipRow 4))
          (tadd (trow (membershipRow 3))
            (tadd (trow (membershipRow 2))
              (tadd (trow (membershipRow 0)) (trow (membershipRow 1)))))))
        (tconst 1))
  | .membershipFresh slot => tmul (trow (approvedRow slot))
      (tmul (trow approvalRow) (trow (membershipRow slot)))
  | .nextBitmap slot => tmul (trow approvalRow)
      (tsub (tsub (trow (nextApprovedRow slot)) (trow (approvedRow slot)))
        (trow (membershipRow slot)))
  | .fullTag slot limb => tmul (tmul (trow approvalRow)
      (trow (membershipRow slot)))
      (tsub (trow (legacyTagRow limb)) (trow (policyTagRow slot limb)))
  | .policyDigestBridge _ => tmul (trow 282) (tsub (trow 280) (trow 281))
  | .inputAuthorization input =>
      let flag := tpub input.val
      let approvalCommitment := if input.val = 0 then
        trow boundCurrentVectorRow else trow legacyVectorRow
      let finalCommitment := if input.val = 0 then
        trow boundSecondaryVectorRow else trow boundCurrentVectorRow
      let expected := tmul flag
        (tadd (tmul (trow singleRow) (trow legacyVectorRow))
          (tadd (tmul (trow approvalRow) approvalCommitment)
            (tmul (trow finalRow) finalCommitment)))
      tsub (trow (inputNoteVectorRow input)) expected
  | .finalIntent limb => tmul (trow finalRow)
      (tsub (trow (129 + limb.val)) (trow (115 + limb.val)))
  | .outputAuthorization => tmul (trow approvalRow)
      (tsub (trow outputZeroVectorRow) (trow boundSecondaryVectorRow))
  | .secondaryInput => tsub (trow secondaryInputVectorRow)
      (tadd (tmul (trow nextVectorRow)
        (tadd (trow singleRow) (trow approvalRow)))
        (tmul (trow finalRow) (trow valueLockVectorRow)))

/-- Finite regenerated data.  `realizes` is a syntax tree of exact source
lookups; it cannot assert the desired implication for arbitrary witnesses. -/
structure CurrentLocalArtifactCertificate
    (components : RelationProgramComponents) where
  nonlinearRoots : components.nonlinearExecutable.roots.length = 818
  canonical : components.nonlinearExecutable.Canonical true
  rootFor : LocalCheck → Nat
  rootMember : ∀ check, rootFor check ∈ components.nonlinearExecutable.roots
  realizes : ∀ check, Realizes components.nonlinearExecutable.expressions
    (rootFor check) (localCheckTerm check)
  witnessRows : relationRowCount = 686
  packingLanes : packingFactor = 64

def LocalSemanticRelation (publicWords rows : List Nat) : Prop :=
  ∀ check, (localCheckTerm check).eval
    (fun index => (publicWords.getD index 0 : Goldilocks))
    (fun row => (rows.getD row 0 : Goldilocks)) = 0

/-- Current packed program acceptance implies the exact local T1--T5,
one-hot transition, seven-limb membership, and output-authorization equations
for every packed lane. -/
theorem packed_program_implies_local_semantics
    {components : RelationProgramComponents}
    (certificate : CurrentLocalArtifactCertificate components)
    {publicWords packedWitness : List Nat}
    (accepted : components.AcceptsPacked publicWords packedWitness)
    (lane : Fin 64) :
    LocalSemanticRelation publicWords
      (packedWitnessLaneRows packedWitness lane.val) := by
  intro check
  have laneBound : lane.val < packingFactor := by
    exact lane.isLt
  have laneAccepted := accepted_packed_program_checks_every_nonlinear_lane accepted laneBound
  obtain ⟨values, evaluated, rootZero⟩ :=
    acceptance_makes_each_named_root_zero laneAccepted (certificate.rootMember check)
  have rootBound := certificate.canonical.2 _ (certificate.rootMember check)
  have refined := fieldAt_refines_source components.nonlinearExecutable
    publicWords (packedWitnessLaneRows packedWitness lane.val) values
    certificate.canonical evaluated (certificate.rootFor check) rootBound
  have valueZero : values.getD (certificate.rootFor check) 0 = 0 := by
    simp [List.getD_eq_getElem?_getD, rootZero]
  rw [fieldAt_of_realizes (certificate.realizes check)] at refined
  rw [valueZero] at refined
  exact refined

/-! ## Direct typed consequences consumed by the registry -/

theorem local_t1_equation {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows) :
    t1Term.eval (fun i => (publicWords.getD i 0 : Goldilocks))
      (fun r => (rows.getD r 0 : Goldilocks)) = 0 := semantic .t1

theorem local_activity_boolean {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows) (index : Fin 4) :
    (publicWords.getD index.val 0 : Goldilocks) = 0 ∨
      (publicWords.getD index.val 0 : Goldilocks) = 1 := by
  have equation := semantic (.activityBoolean index)
  simpa [localCheckTerm, SourceTerm.eval, mul_eq_zero, sub_eq_zero] using equation

theorem local_t2_equation {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows) :
    t2Term.eval (fun i => (publicWords.getD i 0 : Goldilocks))
      (fun r => (rows.getD r 0 : Goldilocks)) = 0 := semantic .t2

theorem local_all_six_t3 {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows) :
    ∀ index : Fin 6,
      (t3Term index).eval (fun i => (publicWords.getD i 0 : Goldilocks))
        (fun r => (rows.getD r 0 : Goldilocks)) = 0 :=
  fun index => semantic (.t3 index)

theorem local_t1_selected_values_ne_zero {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows) :
    let pubEval := fun index => (publicWords.getD index 0 : Goldilocks)
    let witness := fun row => (rows.getD row 0 : Goldilocks)
    (pubEval 0 * (witness singleRow + witness finalRow) = 1 →
      witness (inputValueRow 0) ≠ 0) ∧
    (pubEval 1 * (witness singleRow + witness approvalRow) = 1 →
      witness (inputValueRow 1) ≠ 0) := by
  dsimp only
  have root := semantic .t1
  have equation : t1Product (rows.getD inputInverseRow 0 : Goldilocks)
      (rows.getD singleRow 0 : Goldilocks) (rows.getD approvalRow 0 : Goldilocks)
      (rows.getD finalRow 0 : Goldilocks)
      (publicWords.getD 0 0 : Goldilocks) (publicWords.getD 1 0 : Goldilocks)
      (rows.getD (inputValueRow 0) 0 : Goldilocks)
      (rows.getD (inputValueRow 1) 0 : Goldilocks) = 1 := by
    have productMinusOne :
        t1Product (rows.getD inputInverseRow 0 : Goldilocks)
          (rows.getD singleRow 0 : Goldilocks) (rows.getD approvalRow 0 : Goldilocks)
          (rows.getD finalRow 0 : Goldilocks)
          (publicWords.getD 0 0 : Goldilocks) (publicWords.getD 1 0 : Goldilocks)
          (rows.getD (inputValueRow 0) 0 : Goldilocks)
          (rows.getD (inputValueRow 1) 0 : Goldilocks) - 1 = 0 := by
      calc
        _ = t1Term.eval
            (fun i => (publicWords.getD i 0 : Goldilocks))
            (fun r => (rows.getD r 0 : Goldilocks)) := by
              simp only [t1Product, selectedPairProduct, selectedValue,
                t1Term, phiTerm, SourceTerm.eval]
              ring
        _ = 0 := root
    exact sub_eq_zero.mp productMinusOne
  exact t1_selected_values_ne_zero equation

theorem local_t2_selected_values_ne_zero {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows) :
    let pubEval := fun index => (publicWords.getD index 0 : Goldilocks)
    let witness := fun row => (rows.getD row 0 : Goldilocks)
    (pubEval 2 * (witness singleRow + witness finalRow) = 1 →
      witness (outputValueRow 0) ≠ 0) ∧
    (pubEval 3 = 1 → witness (outputValueRow 1) ≠ 0) := by
  dsimp only
  have root := semantic .t2
  have equation : t2Product (rows.getD outputInverseRow 0 : Goldilocks)
      (rows.getD singleRow 0 : Goldilocks) (rows.getD finalRow 0 : Goldilocks)
      (publicWords.getD 2 0 : Goldilocks) (publicWords.getD 3 0 : Goldilocks)
      (rows.getD (outputValueRow 0) 0 : Goldilocks)
      (rows.getD (outputValueRow 1) 0 : Goldilocks) = 1 := by
    have productMinusOne :
        t2Product (rows.getD outputInverseRow 0 : Goldilocks)
          (rows.getD singleRow 0 : Goldilocks) (rows.getD finalRow 0 : Goldilocks)
          (publicWords.getD 2 0 : Goldilocks) (publicWords.getD 3 0 : Goldilocks)
          (rows.getD (outputValueRow 0) 0 : Goldilocks)
          (rows.getD (outputValueRow 1) 0 : Goldilocks) - 1 = 0 := by
      calc
        _ = t2Term.eval
            (fun i => (publicWords.getD i 0 : Goldilocks))
            (fun r => (rows.getD r 0 : Goldilocks)) := by
              simp only [t2Product, selectedPairProduct, selectedValue,
                t2Term, phiTerm, SourceTerm.eval]
              ring
        _ = 0 := root
    exact sub_eq_zero.mp productMinusOne
  exact t2_selected_values_ne_zero equation

theorem local_full_seven_tag_membership {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows) :
    ∀ slot : SignerSlot, ∀ limb : Fin 7,
      (localCheckTerm (.fullTag slot limb)).eval
        (fun i => (publicWords.getD i 0 : Goldilocks))
        (fun r => (rows.getD r 0 : Goldilocks)) = 0 :=
  fun slot limb => semantic (.fullTag slot limb)

theorem local_selected_full_tag_equality {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (approvalSelected : (rows.getD approvalRow 0 : Goldilocks) = 1)
    (slot : SignerSlot)
    (membershipSelected : (rows.getD (membershipRow slot) 0 : Goldilocks) = 1) :
    (fun limb : Fin 7 => (rows.getD (legacyTagRow limb) 0 : Goldilocks)) =
      (fun limb : Fin 7 =>
        (rows.getD (policyTagRow slot limb) 0 : Goldilocks)) := by
  funext limb
  have equation := semantic (.fullTag slot limb)
  simp only [localCheckTerm, SourceTerm.eval, approvalSelected,
    membershipSelected, one_mul] at equation
  exact sub_eq_zero.mp equation

theorem local_approval_zero_native_roles {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (approvalSelected : (rows.getD approvalRow 0 : Goldilocks) = 1) :
    (rows.getD (inputValueRow 0) 0 : Goldilocks) = 0 ∧
    (rows.getD (inputAssetRow 0) 0 : Goldilocks) = 0 ∧
    (rows.getD (outputValueRow 0) 0 : Goldilocks) = 0 ∧
    (rows.getD (outputAssetRow 0) 0 : Goldilocks) = 0 := by
  have h0 := semantic (.t3 (0 : Fin 6))
  have h1 := semantic (.t3 (1 : Fin 6))
  have h2 := semantic (.t3 (2 : Fin 6))
  have h3 := semantic (.t3 (3 : Fin 6))
  simp only [localCheckTerm, t3Term, SourceTerm.eval, List.get,
    approvalSelected, mul_one] at h0 h1 h2 h3
  exact ⟨h0, h1, h2, h3⟩

theorem local_final_accumulator_zero_native {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (finalSelected : (rows.getD finalRow 0 : Goldilocks) = 1) :
    (rows.getD (inputValueRow 1) 0 : Goldilocks) = 0 ∧
      (rows.getD (inputAssetRow 1) 0 : Goldilocks) = 0 := by
  have h4 := semantic (.t3 (4 : Fin 6))
  have h5 := semantic (.t3 (5 : Fin 6))
  simp only [localCheckTerm, t3Term, SourceTerm.eval, List.get,
    finalSelected, mul_one] at h4 h5
  exact ⟨h4, h5⟩

theorem local_approval_output_full_authorization {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (approvalSelected : (rows.getD approvalRow 0 : Goldilocks) = 1) :
    (rows.getD outputZeroVectorRow 0 : Goldilocks) =
      (rows.getD boundSecondaryVectorRow 0 : Goldilocks) := by
  have equation := semantic .outputAuthorization
  simp only [localCheckTerm, SourceTerm.eval, approvalSelected, one_mul] at equation
  exact sub_eq_zero.mp equation

theorem local_approval_input_zero_authorization {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (approvalSelected : (rows.getD approvalRow 0 : Goldilocks) = 1)
    (singleUnselected : (rows.getD singleRow 0 : Goldilocks) = 0)
    (finalUnselected : (rows.getD finalRow 0 : Goldilocks) = 0)
    (inputActive : (publicWords.getD 0 0 : Goldilocks) = 1) :
    (rows.getD (inputNoteVectorRow 0) 0 : Goldilocks) =
      (rows.getD boundCurrentVectorRow 0 : Goldilocks) := by
  have equation := semantic (.inputAuthorization 0)
  change (rows.getD (inputNoteVectorRow 0) 0 : Goldilocks) -
    (publicWords.getD 0 0 : Goldilocks) *
      ((rows.getD singleRow 0 : Goldilocks) *
          (rows.getD legacyVectorRow 0 : Goldilocks) +
        ((rows.getD approvalRow 0 : Goldilocks) *
            (rows.getD boundCurrentVectorRow 0 : Goldilocks) +
          (rows.getD finalRow 0 : Goldilocks) *
            (rows.getD boundSecondaryVectorRow 0 : Goldilocks))) = 0 at equation
  rw [approvalSelected, singleUnselected, finalUnselected, inputActive] at equation
  simp only [one_mul, zero_mul, zero_add, add_zero] at equation
  exact sub_eq_zero.mp equation

theorem local_final_input_one_authorization {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (finalSelected : (rows.getD finalRow 0 : Goldilocks) = 1)
    (singleUnselected : (rows.getD singleRow 0 : Goldilocks) = 0)
    (approvalUnselected : (rows.getD approvalRow 0 : Goldilocks) = 0)
    (inputActive : (publicWords.getD 1 0 : Goldilocks) = 1) :
    (rows.getD (inputNoteVectorRow 1) 0 : Goldilocks) =
      (rows.getD boundCurrentVectorRow 0 : Goldilocks) := by
  have equation := semantic (.inputAuthorization 1)
  change (rows.getD (inputNoteVectorRow 1) 0 : Goldilocks) -
    (publicWords.getD 1 0 : Goldilocks) *
      ((rows.getD singleRow 0 : Goldilocks) *
          (rows.getD legacyVectorRow 0 : Goldilocks) +
        ((rows.getD approvalRow 0 : Goldilocks) *
            (rows.getD legacyVectorRow 0 : Goldilocks) +
          (rows.getD finalRow 0 : Goldilocks) *
            (rows.getD boundCurrentVectorRow 0 : Goldilocks))) = 0 at equation
  rw [finalSelected, singleUnselected, approvalUnselected, inputActive] at equation
  simp only [one_mul, zero_mul, zero_add] at equation
  exact sub_eq_zero.mp equation

/-- The actual source mux, not an assumed choice of secondary digest. -/
theorem local_approval_secondary_input {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (approvalSelected : (rows.getD approvalRow 0 : Goldilocks) = 1)
    (singleUnselected : (rows.getD singleRow 0 : Goldilocks) = 0)
    (finalUnselected : (rows.getD finalRow 0 : Goldilocks) = 0) :
    (rows.getD secondaryInputVectorRow 0 : Goldilocks) =
      (rows.getD nextVectorRow 0 : Goldilocks) := by
  have equation := semantic .secondaryInput
  simp only [localCheckTerm, SourceTerm.eval] at equation
  rw [approvalSelected, singleUnselected, finalUnselected] at equation
  simp only [zero_add, zero_mul, mul_one, add_zero] at equation
  exact sub_eq_zero.mp equation

theorem local_final_secondary_input {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (finalSelected : (rows.getD finalRow 0 : Goldilocks) = 1)
    (singleUnselected : (rows.getD singleRow 0 : Goldilocks) = 0)
    (approvalUnselected : (rows.getD approvalRow 0 : Goldilocks) = 0) :
    (rows.getD secondaryInputVectorRow 0 : Goldilocks) =
      (rows.getD valueLockVectorRow 0 : Goldilocks) := by
  have equation := semantic .secondaryInput
  simp only [localCheckTerm, SourceTerm.eval] at equation
  rw [finalSelected, singleUnselected, approvalUnselected] at equation
  simp only [zero_add, mul_zero, one_mul, add_zero] at equation
  exact sub_eq_zero.mp equation

theorem local_approval_bootstrap_iff
    {publicWords rows : List Nat}
    (semantic : LocalSemanticRelation publicWords rows)
    (count : Fin 7)
    (approvalSelected : (rows.getD approvalRow 0 : Goldilocks) = 1)
    (inputBoolean : (publicWords.getD 0 0 : Goldilocks) = 0 ∨
      (publicWords.getD 0 0 : Goldilocks) = 1)
    (countProjection : (count.val : Goldilocks) =
      (rows.getD countRow 0 : Goldilocks)) :
    (publicWords.getD 0 0 : Goldilocks) = 0 ↔ count.val = 0 := by
  let approval : Goldilocks := rows.getD approvalRow 0
  let input0 : Goldilocks := publicWords.getD 0 0
  have t4 : T4 approval input0 count := by
    have equation := semantic .t4
    change (rows.getD countRow 0 : Goldilocks) *
      ((rows.getD approvalRow 0 : Goldilocks) *
        (1 - (publicWords.getD 0 0 : Goldilocks))) = 0 at equation
    rw [approvalSelected] at equation
    simp only [one_mul] at equation
    rw [← countProjection] at equation
    change approval * (1 - input0) * (count.val : Goldilocks) = 0
    dsimp only [approval]
    rw [approvalSelected]
    calc
      _ = (count.val : Goldilocks) *
          (1 - (publicWords.getD 0 0 : Goldilocks)) := by
            dsimp [input0]
            ring
      _ = 0 := equation
  have t5 : T5 approval input0 count := by
    have equation := semantic .t5
    have productEval :
        (productTerms ((List.range 6).map fun offset =>
          tsub (trow countRow) (tconst (offset + 1)))).eval
            (fun i => (publicWords.getD i 0 : Goldilocks))
            (fun r => (rows.getD r 0 : Goldilocks)) =
          approvalRangeProduct (rows.getD countRow 0 : Goldilocks) := by
      have range6 : List.range 6 = [0, 1, 2, 3, 4, 5] := rfl
      simp [range6, productTerms, SourceTerm.eval, approvalRangeProduct]
    change (publicWords.getD 0 0 : Goldilocks) *
      (rows.getD approvalRow 0 : Goldilocks) *
      (productTerms ((List.range 6).map fun offset =>
        tsub (trow countRow) (tconst (offset + 1)))).eval
          (fun i => (publicWords.getD i 0 : Goldilocks))
          (fun r => (rows.getD r 0 : Goldilocks)) = 0 at equation
    rw [productEval, approvalSelected] at equation
    rw [← countProjection] at equation
    simp only [mul_one] at equation
    change approval * input0 *
      approvalRangeProduct (count.val : Goldilocks) = 0
    dsimp only [approval]
    rw [approvalSelected]
    dsimp [input0]
    simp only [one_mul]
    exact equation
  exact approval_input_inactive_iff_count_zero approvalSelected inputBoolean t4 t5

/-- Exact routine regeneration inventory.  These are data checks, not an
additional semantic assumption. -/
structure RegenerationInventory where
  nonlinearRootCount : Nat := 818
  /-- Regenerated RP05 value; deliberately unpinned until the current exporter
  emits it.  `8130` belonged to the old RP04 artifact. -/
  expressionNodeCount : Option Nat := none
  witnessRowCount : Nat := 686
  packingLaneCount : Nat := 64
  authorizationRowsUsed : Nat := 139
  authorizationRowsAvailable : Nat := 155
  signerTagWords : Nat := 7
  intentWords : Nat := 104
  policyWords : Nat := 44
  hashCalls : Nat := 128
  policyFinalCall : Nat := 99
  boundCurrentCall : Nat := 107
  boundSecondaryCall : Nat := 108

inductive RequiredCsrBinding where
  | actionIntent104
  | authorizationSpongeFrameAndPadding
  | policyOpening44
  | policyFinalDigest7
  | currentAccumulatorSource23
  | nextAccumulatorSource23
  | boundCurrentDigest7
  | boundSecondaryDigest7
deriving DecidableEq

/-- Exact finite CSR/source checks still required from the current exporter.
Each item is a coordinate equality/attempt lookup; none is a universal
witness-semantic implication. -/
def requiredCsrBindings : List RequiredCsrBinding :=
  [.actionIntent104, .authorizationSpongeFrameAndPadding,
    .policyOpening44, .policyFinalDigest7,
    .currentAccumulatorSource23, .nextAccumulatorSource23,
    .boundCurrentDigest7, .boundSecondaryDigest7]

def requiredLocalRoots : List LocalCheck :=
  [.modeOneHot, .t1, .t2, .t4, .t5, .approvalInputOne, .approvalOutputZero,
    .nextCount, .membershipOneHot, .outputAuthorization, .secondaryInput] ++
  (List.ofFn fun index : Fin 4 => LocalCheck.activityBoolean index) ++
  (List.ofFn fun mode : Fin 3 => LocalCheck.modeBoolean mode) ++
  (List.ofFn fun input : Fin 2 => LocalCheck.inputAuthorization input) ++
  (List.ofFn fun limb : Fin 7 => LocalCheck.finalIntent limb) ++
  (List.ofFn fun index : Fin 6 => LocalCheck.t3 index) ++
  (List.ofFn fun slot : SignerSlot =>
    [.membershipBoolean slot, .membershipFresh slot, .nextBitmap slot]).flatten ++
  (List.ofFn fun slot : SignerSlot =>
    List.ofFn fun limb : Fin 7 => LocalCheck.fullTag slot limb).flatten
  ++ (List.ofFn fun limb : Fin 7 => LocalCheck.policyDigestBridge limb)

def currentRegenerationInventory : RegenerationInventory := {}

end HegemonCrypto.SmallWood.SmzaRp05TypedRelation
