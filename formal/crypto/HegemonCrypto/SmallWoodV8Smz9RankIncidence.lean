import Mathlib.LinearAlgebra.Dimension.Constructions
import Mathlib.LinearAlgebra.LinearIndependent.Lemmas
import Mathlib.GroupTheory.Coset.Basic
import Mathlib.Data.Finset.Powerset
import Mathlib.Algebra.BigOperators.Group.Finset.Basic

/-!
# Rank witnesses for adaptive agreement sets

Research lemmas for the full-matrix DECS experiment.  The extension theorem derives
independent supports from span dimension; the counting theorem counts their overlaps.
The affine-fiber theorem counts solutions of an actual surjective linear map.

The exact SMZ9 binding still needs its Vandermonde projection, the rank of the data
map modulo the restricted Reed--Solomon code, identification of its five matrix rows
with the proved product count, and the committed-oracle / fresh-challenge experiment.
No accepted-proof or QROM theorem is asserted.
-/

namespace HegemonCrypto.SmallWood.V8Smz9RankIncidence

open scoped BigOperators
open Module Submodule

noncomputable section

variable {F D V W : Type*} [Field F] [Fintype D]
  [AddCommGroup V] [Module F V] [AddCommGroup W] [Module F W]

/-- Extend an independent support inside a given domain to any size at most the
dimension of that domain's vector span.  No extension or witness-density premise
is supplied by the caller. -/
theorem exists_independent_extension (v : D → V) (J G : Finset D) (m : ℕ)
    (hJG : J ⊆ G) (hJ : LinearIndepOn F v (J : Set D))
    (hJm : J.card ≤ m)
    (hm : m ≤ finrank F (span F (v '' (G : Set D)))) :
    ∃ I : Finset D, J ⊆ I ∧ I ⊆ G ∧ I.card = m ∧
      LinearIndepOn F v (I : Set D) := by
  classical
  have hsub : (J : Set D) ⊆ (G : Set D) := hJG
  let E : Finset D := (hJ.extend hsub).toFinset
  have hJE : J ⊆ E := by simpa [E] using hJ.subset_extend hsub
  have hEG : E ⊆ G := by simpa [E] using hJ.extend_subset hsub
  have hE : LinearIndepOn F v (E : Set D) := by
    simpa [E] using hJ.linearIndepOn_extend hsub
  have hspan : span F (v '' (E : Set D)) = span F (v '' (G : Set D)) := by
    simpa [E] using hJ.span_image_extend_eq_span_image hsub
  have hmE : m ≤ E.card := by
    calc
      m ≤ finrank F (span F (v '' (G : Set D))) := hm
      _ = finrank F (span F (v '' (E : Set D))) := by rw [hspan]
      _ ≤ (E.image v).card := by
        have himage : ((E.image v : Finset V) : Set V) = v '' (E : Set D) := by
          ext x
          simp
        rw [← himage]
        exact finrank_span_finset_le_card (R := F) (E.image v)
      _ ≤ E.card := Finset.card_image_le
  obtain ⟨I, hJI, hIE, hcard⟩ := Finset.exists_subsuperset_card_eq hJE hJm hmE
  exact ⟨I, hJI, hIE.trans hEG, hcard, hE.mono hIE⟩

/-- Independent supports of the specified size, within the specified domain. -/
def independentSupports (v : D → V) (G : Finset D) (m : ℕ) : Finset (Finset D) := by
  classical
  exact (G.powersetCard m).filter fun I => LinearIndepOn F v (I : Set D)

/-- Each base support extends, and each independent support contains exactly
`choose m k` possible base supports.  The resulting density is proved by counting
the same finite incidences in the two orders. -/
theorem independent_support_count (v : D → V) (G : Finset D) (k m : ℕ)
    (hkm : k ≤ m)
    (hbase : ∀ J ∈ G.powersetCard k, LinearIndepOn F v (J : Set D))
    (hm : m ≤ finrank F (span F (v '' (G : Set D)))) :
    G.card.choose k ≤ (independentSupports (F := F) v G m).card * m.choose k := by
  classical
  let S := G.powersetCard k
  let T := independentSupports (F := F) v G m
  have hlow : ∀ J ∈ S, 1 ≤ (T.filter fun I => J ⊆ I).card := by
    intro J hJ
    obtain ⟨hJG, hJcard⟩ := Finset.mem_powersetCard.mp hJ
    obtain ⟨I, hJI, hIG, hIcard, hI⟩ :=
      exists_independent_extension v J G m hJG (hbase J hJ) (hJcard ▸ hkm) hm
    apply Finset.one_le_card.mpr
    exact ⟨I, Finset.mem_filter.mpr
      ⟨Finset.mem_filter.mpr ⟨Finset.mem_powersetCard.mpr ⟨hIG, hIcard⟩, hI⟩, hJI⟩⟩
  have hupp : ∀ I ∈ T, (S.filter fun J => J ⊆ I).card ≤ m.choose k := by
    intro I hI
    have hIcard : I.card = m := (Finset.mem_powersetCard.mp
      (Finset.mem_filter.mp hI).1).2
    calc
      (S.filter fun J => J ⊆ I).card ≤ (I.powersetCard k).card := by
        apply Finset.card_le_card
        intro J hJ
        obtain ⟨hJS, hJI⟩ := Finset.mem_filter.mp hJ
        exact Finset.mem_powersetCard.mpr ⟨hJI, (Finset.mem_powersetCard.mp hJS).2⟩
      _ = m.choose k := by rw [Finset.card_powersetCard, hIcard]
  calc
    G.card.choose k = ∑ _J ∈ S, 1 := by simp [S]
    _ ≤ ∑ J ∈ S, (T.filter fun I => J ⊆ I).card := Finset.sum_le_sum hlow
    _ = ∑ I ∈ T, (S.filter fun J => J ⊆ I).card := by
      simp only [Finset.card_eq_sum_ones, Finset.sum_filter]
      exact Finset.sum_comm
    _ ≤ ∑ _I ∈ T, m.choose k := Finset.sum_le_sum hupp
    _ = T.card * m.choose k := by simp

/-- Translation identifies each nonempty affine linear fiber with the zero fiber. -/
theorem affine_fiber_card_eq_kernel [Fintype V]
    (L : V →ₗ[F] W) (hL : Function.Surjective L) (b : W) :
    Nat.card {x : V // L x = b} = Nat.card L.ker := by
  classical
  exact Nat.card_congr
    (AddMonoidHom.fiberEquivKerOfSurjective (f := L.toAddMonoidHom) hL b)

/-- Equal-size affine fibers partition the whole source.  This exact integer
identity is the uniform probability `1 / card W`, with no probability assumption. -/
theorem affine_fiber_card_mul_target [Fintype V] [Fintype W]
    (L : V →ₗ[F] W) (hL : Function.Surjective L) (b : W) :
    Nat.card {x : V // L x = b} * Nat.card W = Nat.card V := by
  classical
  have hpartition := Fintype.card_congr (Equiv.sigmaFiberEquiv L)
  rw [Fintype.card_sigma] at hpartition
  simp only [← Nat.card_eq_fintype_card] at hpartition
  simp_rw [affine_fiber_card_eq_kernel L hL] at hpartition
  rw [affine_fiber_card_eq_kernel L hL]
  simpa only [Finset.sum_const, Finset.card_univ, nsmul_eq_mul,
    ← Nat.card_eq_fintype_card, Nat.cast_id, Nat.mul_comm] using hpartition

/-- Apply the same residual map separately to every independently sampled row. -/
def rowMap (L : V →ₗ[F] W) (eta : ℕ) : (Fin eta → V) →ₗ[F] (Fin eta → W) where
  toFun a i := L (a i)
  map_add' a b := by ext i; exact L.map_add (a i) (b i)
  map_smul' c a := by ext i; exact L.map_smul c (a i)

theorem rowMap_surjective (L : V →ₗ[F] W) (hL : Function.Surjective L) (eta : ℕ) :
    Function.Surjective (rowMap L eta) := by
  intro b
  choose a ha using fun i => hL (b i)
  exact ⟨a, funext ha⟩

/-- Exact simultaneous affine-constraint count.  With `eta = 5` this is the
`p^(5*r)` denominator; the offset may differ between rows but is fixed during
the count over the entire matrix space. -/
theorem independent_affine_rows_card [Fintype F] [Fintype V]
    (r eta : ℕ) (L : V →ₗ[F] (Fin r → F)) (hL : Function.Surjective L)
    (b : Fin eta → Fin r → F) :
    Nat.card {a : Fin eta → V // ∀ i, L (a i) = b i} *
      (Nat.card F) ^ (r * eta) = (Nat.card V) ^ eta := by
  classical
  have h := affine_fiber_card_mul_target (rowMap L eta) (rowMap_surjective L hL eta) b
  let he : {a : Fin eta → V // rowMap L eta a = b} ≃
      {a : Fin eta → V // ∀ i, L (a i) = b i} := {
    toFun a := ⟨a, fun i => congrFun a.property i⟩
    invFun a := ⟨a, funext a.property⟩
    left_inv a := rfl
    right_inv a := rfl }
  rw [Nat.card_congr he] at h
  simpa only [Nat.card_eq_fintype_card, Fintype.card_fun, Fintype.card_fin, ← pow_mul] using h

/-- If code and data contributions together span the support, data alone maps
onto the support modulo the code.  This constructs the residual surjectivity
needed by the affine count, rather than assuming its solution probability. -/
theorem quotient_data_map_surjective {U : Type*} [AddCommGroup U] [Module F U]
    (code : U →ₗ[F] W) (data : V →ₗ[F] W)
    (hfull : Function.Surjective (code.coprod data)) :
    Function.Surjective ((LinearMap.range code).mkQ.comp data) := by
  intro q
  obtain ⟨w, rfl⟩ := (LinearMap.range code).mkQ_surjective q
  obtain ⟨⟨u, a⟩, hwa⟩ := hfull w
  refine ⟨a, ?_⟩
  change (LinearMap.range code).mkQ (data a) = (LinearMap.range code).mkQ w
  rw [← hwa]
  change (LinearMap.range code).mkQ (data a) =
    (LinearMap.range code).mkQ (code u + data a)
  rw [map_add]
  have hz : (LinearMap.range code).mkQ (code u) = 0 := by
    exact (Submodule.Quotient.mk_eq_zero (LinearMap.range code)).mpr ⟨u, rfl⟩
  rw [hz, zero_add]

/-- Number of affine support constraints satisfied by one challenge. -/
def affineSupportCount (S : Finset D) (L : D → V →ₗ[F] W) (b : D → W) (a : V) : ℕ := by
  classical
  exact (S.filter fun i => L i a = b i).card

omit [Fintype D] in
/-- The exact first-moment incidence identity follows from linear fibers and
double counting, even though different support events may overlap arbitrarily. -/
theorem affine_incidence_sum [Fintype V] [Fintype W]
    (S : Finset D) (L : D → V →ₗ[F] W) (b : D → W)
    (hL : ∀ i ∈ S, Function.Surjective (L i)) :
    (∑ a : V, affineSupportCount S L b a) * Nat.card W = S.card * Nat.card V := by
  classical
  have hswap : (∑ a : V, affineSupportCount S L b a) =
      ∑ i ∈ S, Nat.card {a : V // L i a = b i} := by
    simp only [affineSupportCount, Nat.card_eq_fintype_card, Fintype.card_subtype,
      Finset.card_eq_sum_ones, Finset.sum_filter]
    exact Finset.sum_comm
  rw [hswap, Finset.sum_mul]
  calc
    (∑ i ∈ S, Nat.card {a : V // L i a = b i} * Nat.card W) =
        ∑ _i ∈ S, Nat.card V := by
      apply Finset.sum_congr rfl
      intro i hi
      exact affine_fiber_card_mul_target (L i) (hL i hi) (b i)
    _ = S.card * Nat.card V := by simp

end

end HegemonCrypto.SmallWood.V8Smz9RankIncidence
