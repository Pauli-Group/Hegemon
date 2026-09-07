import HegemonCrypto.SmallWoodV8Smz9HonestHybrid

/-!
# Fresh taped inputs for the first honest-leaf QROM hybrid

This module constructs the finite fresh-input law and proves its exact point probabilities.
It also defines the full finite coherent oracle-query operator, splits a uniform oracle into
independent disjoint-domain tables, and proves exact two-query clean-ancilla simulation.
It does NOT formalize or assume
the adaptive-reprogramming distance theorem. That published theorem and the reduction using
these constructors are stated separately in hidden-leaf-qrom-step.md.

For the source's 53-byte profile, 42-byte role, 160 raw words and counter zero, the complete
pre-padding SHA-512 input is 1407 bytes. Tape bytes occupy positions 159 through 222. Prefix
and suffix here are arbitrary fixed bytes; therefore the proof covers the source's exact
framing without relying on its field values. Rust serialization and OS randomness are not
certified by this mathematical byte-array constructor.
-/

namespace HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom

open V8Smz9RuntimeDistribution
open scoped ENNReal BigOperators Classical

noncomputable section

set_option maxRecDepth 2048

abbrev Byte := Fin 256
abbrev LeafTape := Fin 64 → Byte
abbrev LeafInput := Fin 1407 → Byte
abbrev LeafPrefix := Fin 159 → Byte
abbrev LeafSuffix := Fin 1184 → Byte

def tapedLeafInput (leading : LeafPrefix) (suffix : LeafSuffix)
    (tape : LeafTape) : LeafInput :=
  Fin.append leading (Fin.append tape suffix)

def leafTapeProjection (input : LeafInput) : LeafTape :=
  fun byte => input (Fin.natAdd 159 (Fin.castAdd 1184 byte))

theorem taped_leaf_projection (leading : LeafPrefix) (suffix : LeafSuffix)
    (tape : LeafTape) : leafTapeProjection (tapedLeafInput leading suffix tape) = tape := by
  funext byte
  simp [leafTapeProjection, tapedLeafInput]

theorem taped_leaf_input_injective (leading : LeafPrefix) (suffix : LeafSuffix) :
    Function.Injective (tapedLeafInput leading suffix) := by
  intro left right equality
  simpa only [taped_leaf_projection] using congrArg leafTapeProjection equality

theorem taped_leaf_prefix_preserved (leading : LeafPrefix) (suffix : LeafSuffix)
    (tape : LeafTape) (byte : Fin 159) :
    tapedLeafInput leading suffix tape (Fin.castAdd 1248 byte) = leading byte := by
  simp [tapedLeafInput]

/-- In particular, any unequal byte in the eight-byte index separates two leaf inputs. -/
theorem unequal_prefix_byte_separates_leaves
    (leftPrefix rightPrefix : LeafPrefix) (leftSuffix rightSuffix : LeafSuffix)
    (leftTape rightTape : LeafTape) (byte : Fin 159)
    (different : leftPrefix byte ≠ rightPrefix byte) :
    tapedLeafInput leftPrefix leftSuffix leftTape ≠
      tapedLeafInput rightPrefix rightSuffix rightTape := by
  intro equality
  apply different
  simpa only [taped_leaf_prefix_preserved] using
    congrFun equality (Fin.castAdd 1248 byte)

theorem leaf_tape_cardinality : Fintype.card LeafTape = 2 ^ 512 := by
  simp only [LeafTape, Byte, Fintype.card_fun, Fintype.card_fin]
  rw [show (256 : ℕ) = 2 ^ 8 by decide, ← pow_mul]

/-- The law's only new coins are the independent 64 uniform bytes. -/
def freshLeafInputLaw (leading : LeafPrefix) (suffix : LeafSuffix) : PMF LeafInput :=
  pmfMap (uniformFintypePMF LeafTape) (tapedLeafInput leading suffix)

theorem fresh_leaf_input_exact_point_mass (leading : LeafPrefix) (suffix : LeafSuffix)
    (tape : LeafTape) :
    freshLeafInputLaw leading suffix (tapedLeafInput leading suffix tape) =
      (2 ^ 512 : ℝ≥0∞)⁻¹ := by
  classical
  rw [freshLeafInputLaw, pmfMap_apply]
  simp only [uniformFintypePMF_apply, tsum_fintype]
  rw [Finset.sum_eq_single_of_mem tape (Finset.mem_univ tape)]
  · simp only [ite_true, leaf_tape_cardinality, Nat.cast_pow, Nat.cast_ofNat]
  · intro other _ different
    rw [if_neg]
    intro equality
    exact different ((taped_leaf_input_injective leading suffix equality).symm)

theorem fresh_leaf_input_off_support (leading : LeafPrefix) (suffix : LeafSuffix)
    (input : LeafInput)
    (outside : ∀ tape, input ≠ tapedLeafInput leading suffix tape) :
    freshLeafInputLaw leading suffix input = 0 := by
  classical
  rw [freshLeafInputLaw, pmfMap_apply]
  simp only [if_neg (outside _), tsum_zero]

/-- A pointwise theorem for every fixed payload, hence for each history-selected payload. -/
theorem fresh_leaf_input_max_mass (leading : LeafPrefix) (suffix : LeafSuffix)
    (input : LeafInput) :
    freshLeafInputLaw leading suffix input ≤ (2 ^ 512 : ℝ≥0∞)⁻¹ := by
  classical
  by_cases exists_tape : ∃ tape, input = tapedLeafInput leading suffix tape
  · obtain ⟨tape, rfl⟩ := exists_tape
    exact (fresh_leaf_input_exact_point_mass leading suffix tape).le
  · rw [fresh_leaf_input_off_support leading suffix input (by simpa using exists_tape)]
    exact bot_le

abbrev QueryBasis (Input Output Workspace : Type*) := Input × Output × Workspace

/-- For a bitstring response, use a finite additive group with bitwise XOR. -/
def oracleQueryBasisEquiv {Input Output Workspace : Type*} [AddGroup Output]
    (oracle : Input → Output) :
    QueryBasis Input Output Workspace ≃ QueryBasis Input Output Workspace where
  toFun basis := (basis.1, basis.2.1 + oracle basis.1, basis.2.2)
  invFun basis := (basis.1, basis.2.1 - oracle basis.1, basis.2.2)
  left_inv basis := by rcases basis with ⟨input, answer, workspace⟩; simp
  right_inv basis := by rcases basis with ⟨input, answer, workspace⟩; simp

def oracleQueryLinearEquiv {Input Output Workspace : Type*} [AddGroup Output]
    (oracle : Input → Output) :
    (QueryBasis Input Output Workspace → ℂ) ≃ₗ[ℂ]
      (QueryBasis Input Output Workspace → ℂ) where
  toFun state := state ∘ (oracleQueryBasisEquiv oracle).symm
  invFun state := state ∘ oracleQueryBasisEquiv oracle
  left_inv state := by funext basis; simp
  right_inv state := by funext basis; simp
  map_add' _ _ := rfl
  map_smul' _ _ := rfl

theorem oracle_query_preserves_squared_hilbert_norm
    {Input Output Workspace : Type*} [Fintype Input] [Fintype Output] [Fintype Workspace]
    [AddGroup Output] (oracle : Input → Output)
    (state : QueryBasis Input Output Workspace → ℂ) :
    (∑ basis, Complex.normSq (oracleQueryLinearEquiv oracle state basis)) =
      ∑ basis, Complex.normSq (state basis) := by
  exact (oracleQueryBasisEquiv oracle).symm.sum_comp (fun basis => Complex.normSq (state basis))

theorem oracle_query_agrees_away_from_changed_input
    {Input Output Workspace : Type*} [AddGroup Output]
    (oldOracle newOracle : Input → Output) (changed : Input)
    (same_elsewhere : ∀ input, input ≠ changed → oldOracle input = newOracle input)
    (state : QueryBasis Input Output Workspace → ℂ)
    (basis : QueryBasis Input Output Workspace) (outside : basis.1 ≠ changed) :
    oracleQueryLinearEquiv oldOracle state basis =
      oracleQueryLinearEquiv newOracle state basis := by
  change state (basis.1, basis.2.1 - oldOracle basis.1, basis.2.2) = _
  rw [same_elsewhere basis.1 outside]
  rfl

/-- Splitting a random table by a disjoint domain partition is a finite bijection. -/
def oracleDomainSplit (Leaf Other Output : Type*) :
    (Leaf ⊕ Other → Output) ≃ (Leaf → Output) × (Other → Output) :=
  Equiv.sumArrowEquivProdArrow Leaf Other Output

theorem uniform_oracle_domain_split
    {Leaf Other Output : Type*} [Fintype Leaf] [Fintype Other]
    [Fintype Output] [Nonempty Output] :
    pmfMap (uniformFintypePMF (Leaf ⊕ Other → Output))
        (oracleDomainSplit Leaf Other Output) =
      uniformFintypePMF ((Leaf → Output) × (Other → Output)) := by
  exact V8Smz9RuntimeFieldLayout.uniform_pmf_map_equiv
    (oracleDomainSplit Leaf Other Output)

theorem split_uniform_oracle_point_mass_factors
    {Leaf Other Output : Type*} [Fintype Leaf] [Fintype Other]
    [Fintype Output] [Nonempty Output]
    (leaf : Leaf → Output) (other : Other → Output) :
    uniformFintypePMF ((Leaf → Output) × (Other → Output)) (leaf, other) =
      uniformFintypePMF (Leaf → Output) leaf *
        uniformFintypePMF (Other → Output) other := by
  simp only [uniformFintypePMF_apply, Fintype.card_prod, Nat.cast_mul]
  exact ENNReal.mul_inv (Or.inr (by simp)) (Or.inl (by simp))

abbrev QueryAuxBasis (Leaf Other Output Workspace : Type*) :=
  (Leaf ⊕ Other) × Output × Output × Workspace

abbrev DigestRegister := Fin 512 → ZMod 2

theorem digest_register_neg_eq_self (value : DigestRegister) : -value = value := by
  funext bit
  exact ZMod.neg_eq_self_mod_two (value bit)

def routedLeaf {Leaf Other : Type*} (dummy : Leaf) : Leaf ⊕ Other → Leaf :=
  Sum.elim id (fun _ => dummy)

/-- One leaf-table query into an auxiliary response register; routing is oracle-free. -/
def leafComputeEquiv {Leaf Other Output Workspace : Type*} [AddGroup Output]
    (leaf : Leaf → Output) (dummy : Leaf) :
    QueryAuxBasis Leaf Other Output Workspace ≃ QueryAuxBasis Leaf Other Output Workspace where
  toFun b := (b.1, b.2.1, b.2.2.1 + leaf (routedLeaf dummy b.1), b.2.2.2)
  invFun b := (b.1, b.2.1, b.2.2.1 - leaf (routedLeaf dummy b.1), b.2.2.2)
  left_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp
  right_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp

theorem leaf_compute_inverse_is_same_bitstring_query
    {Leaf Other Workspace : Type*} (leaf : Leaf → DigestRegister) (dummy : Leaf)
    (basis : QueryAuxBasis Leaf Other DigestRegister Workspace) :
    (leafComputeEquiv leaf dummy).symm basis = leafComputeEquiv leaf dummy basis := by
  change (basis.1, basis.2.1, basis.2.2.1 - leaf (routedLeaf dummy basis.1), basis.2.2.2) = _
  rw [sub_eq_add_neg, digest_register_neg_eq_self]
  rfl

/-- A known complement table and controlled addition use no leaf-oracle query. -/
def localControlledAnswerEquiv {Leaf Other Output Workspace : Type*} [AddGroup Output]
    (other : Other → Output) :
    QueryAuxBasis Leaf Other Output Workspace ≃ QueryAuxBasis Leaf Other Output Workspace where
  toFun b := (b.1, b.2.1 + Sum.elim (fun _ => b.2.2.1) other b.1, b.2.2.1, b.2.2.2)
  invFun b := (b.1, b.2.1 - Sum.elim (fun _ => b.2.2.1) other b.1, b.2.2.1, b.2.2.2)
  left_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp
  right_inv b := by rcases b with ⟨input, answer, auxiliary, work⟩; simp

/-- Compute, controlled answer, uncompute. For XOR, the inverse query is the same query. -/
def twoQueryFullOracleEquiv {Leaf Other Output Workspace : Type*} [AddGroup Output]
    (leaf : Leaf → Output) (other : Other → Output) (dummy : Leaf) :
    QueryAuxBasis Leaf Other Output Workspace ≃ QueryAuxBasis Leaf Other Output Workspace :=
  ((leafComputeEquiv leaf dummy).trans (localControlledAnswerEquiv other)).trans
    (leafComputeEquiv leaf dummy).symm

theorem two_query_full_oracle_on_clean_auxiliary
    {Leaf Other Output Workspace : Type*} [AddGroup Output]
    (leaf : Leaf → Output) (other : Other → Output) (dummy : Leaf)
    (input : Leaf ⊕ Other) (answer : Output) (work : Workspace) :
    twoQueryFullOracleEquiv leaf other dummy (input, answer, 0, work) =
      (input, answer + Sum.elim leaf other input, 0, work) := by
  cases input <;>
    simp [twoQueryFullOracleEquiv, leafComputeEquiv, localControlledAnswerEquiv, routedLeaf]

/-- The physical linear extension of the exact two-query basis permutation. -/
def twoQueryFullOracleLinearEquiv {Leaf Other Output Workspace : Type*} [AddGroup Output]
    (leaf : Leaf → Output) (other : Other → Output) (dummy : Leaf) :
    (QueryAuxBasis Leaf Other Output Workspace → ℂ) ≃ₗ[ℂ]
      (QueryAuxBasis Leaf Other Output Workspace → ℂ) where
  toFun state := state ∘ (twoQueryFullOracleEquiv leaf other dummy).symm
  invFun state := state ∘ twoQueryFullOracleEquiv leaf other dummy
  left_inv state := by funext basis; simp
  right_inv state := by funext basis; simp
  map_add' _ _ := rfl
  map_smul' _ _ := rfl

theorem two_query_simulation_preserves_squared_hilbert_norm
    {Leaf Other Output Workspace : Type*} [Fintype Leaf] [Fintype Other]
    [Fintype Output] [Fintype Workspace] [AddGroup Output]
    (leaf : Leaf → Output) (other : Other → Output) (dummy : Leaf)
    (state : QueryAuxBasis Leaf Other Output Workspace → ℂ) :
    (∑ basis, Complex.normSq (twoQueryFullOracleLinearEquiv leaf other dummy state basis)) =
      ∑ basis, Complex.normSq (state basis) := by
  exact (twoQueryFullOracleEquiv leaf other dummy).symm.sum_comp
    (fun basis => Complex.normSq (state basis))

def cleanAuxiliaryState {Leaf Other Output Workspace : Type*} [Zero Output]
    (state : QueryBasis (Leaf ⊕ Other) Output Workspace → ℂ) :
    QueryAuxBasis Leaf Other Output Workspace → ℂ :=
  fun basis => if basis.2.2.1 = 0 then state (basis.1, basis.2.1, basis.2.2.2) else 0

/-- Exact coherent simulation on the whole clean-auxiliary subspace, including workspace. -/
theorem two_query_full_oracle_coherent_simulation
    {Leaf Other Output Workspace : Type*} [AddGroup Output]
    (leaf : Leaf → Output) (other : Other → Output) (dummy : Leaf)
    (state : QueryBasis (Leaf ⊕ Other) Output Workspace → ℂ) :
    twoQueryFullOracleLinearEquiv leaf other dummy (cleanAuxiliaryState state) =
      cleanAuxiliaryState (oracleQueryLinearEquiv (Sum.elim leaf other) state) := by
  funext basis
  rcases basis with ⟨input, answer, auxiliary, work⟩
  cases input <;> by_cases clean : auxiliary = 0
  all_goals simp [twoQueryFullOracleLinearEquiv, twoQueryFullOracleEquiv,
    leafComputeEquiv, localControlledAnswerEquiv, routedLeaf, cleanAuxiliaryState,
    oracleQueryLinearEquiv, oracleQueryBasisEquiv, clean]

end

end HegemonCrypto.SmallWood.V8Smz9HiddenLeafQrom
