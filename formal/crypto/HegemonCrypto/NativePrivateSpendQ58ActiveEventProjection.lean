import HegemonCrypto.NativePrivateSpendQ58CurrentRoleClassifier
import SmzaRoleDomainActiveEmbedding

namespace HegemonCrypto.SmallWood.NativePrivateSpendQ58ActiveEventProjection

open scoped Classical BigOperators
open HegemonCrypto.FiniteOracleDatabase HegemonCrypto.CmsCompressedOracle
open HegemonCrypto.CmsOracleSimulation HegemonCrypto.CmsOracleDatabaseBridge
open V8Smz9CoherentVectorMerkle SmzaRp04RawMcaSampling
open SmzaRp05PhysicalTerminalRead SmzaRp05PhysicalReadSupport
open SmzaRoleDomainConditioning (ActiveRouteMemory)

noncomputable section
set_option autoImplicit false
variable {Key Counter Work : Type}

abbrev ActiveKey (live : Key → Prop) := { key : Key // live key }
abbrev FixedTable (live : Key → Prop) :=
  NativePrivateSpendQ58PartitionTransport.FixedTable (Counter := Counter) live
abbrev OriginalRegister := RegisterBasis
  (Input := Key) (Phase := VectorOutput Counter) (Workspace := Work)
abbrev Memory := ActiveRouteMemory Key (VectorOutput Counter) Work
abbrev FullState := State Key (VectorOutput Counter) (VectorOutput Counter) Work
abbrev SparseState (live : Key → Prop) :=
  State (ActiveKey live) (VectorOutput Counter) (VectorOutput Counter)
    (Memory (Key := Key) (Counter := Counter) (Work := Work))

def restrictDatabase (live : Key → Prop)
    (database : Database Key (VectorOutput Counter)) :
    Database (ActiveKey live) (VectorOutput Counter) := fun key => database key.val

def merge (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (database : Database (ActiveKey live) (VectorOutput Counter)) :
    Database Key (VectorOutput Counter) := fun key =>
  if active : live key then database ⟨key, active⟩ else some (fixed ⟨key, active⟩)

@[simp] theorem merge_active (live : Key → Prop)
    (fixed : FixedTable (Counter := Counter) live)
    (database : Database (ActiveKey live) (VectorOutput Counter)) (key : ActiveKey live) :
    merge live fixed database key.val = database key := by simp [merge, key.property]

@[simp] theorem merge_fixed (live : Key → Prop)
    (fixed : FixedTable (Counter := Counter) live)
    (database : Database (ActiveKey live) (VectorOutput Counter))
    (key : NativePrivateSpendQ58PartitionTransport.FixedKey live) :
    merge live fixed database key.val = some (fixed key) := by simp [merge, key.property]

@[simp] theorem restrict_merge (live : Key → Prop)
    (fixed : FixedTable (Counter := Counter) live)
    (database : Database (ActiveKey live) (VectorOutput Counter)) :
    restrictDatabase live (merge live fixed database) = database := by
  funext key
  exact merge_active live fixed database key

@[simp] theorem merge_on_fiber (live : Key → Prop)
    (fixed : FixedTable (Counter := Counter) live)
    (database : Database (ActiveKey live) (VectorOutput Counter)) :
    NativePrivateSpendQ58PartitionTransport.onFiber live fixed (merge live fixed database) := by
  intro key
  exact merge_fixed live fixed database key

theorem merge_restrict (live : Key → Prop)
    (fixed : FixedTable (Counter := Counter) live)
    (database : Database Key (VectorOutput Counter))
    (fiber : NativePrivateSpendQ58PartitionTransport.onFiber live fixed database) :
    merge live fixed (restrictDatabase live database) = database := by
  funext key
  by_cases active : live key
  · simp [merge, restrictDatabase, active]
  · exact (merge_fixed live fixed (restrictDatabase live database) ⟨key, active⟩).trans
      (fiber ⟨key, active⟩).symm

theorem merge_set_active [DecidableEq Key]
    (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (database : Database (ActiveKey live) (VectorOutput Counter))
    (key : ActiveKey live) (coordinate : Option (VectorOutput Counter)) :
    merge live fixed (setDatabaseCoordinate database key coordinate) =
      setDatabaseCoordinate (merge live fixed database) key.val coordinate := by
  funext other
  by_cases same : other = key.val
  · subst other
    simp [merge, key.property, setDatabaseCoordinate]
  · by_cases active : live other
    · have different : (⟨other, active⟩ : ActiveKey live) ≠ key := by
        intro equal
        exact same (congrArg Subtype.val equal)
      simp [merge, active, setDatabaseCoordinate, same, different]
    · simp [merge, active, setDatabaseCoordinate, same]

def route (live : Key → Prop) (dummy : ActiveKey live)
    (original : OriginalRegister (Key := Key) (Counter := Counter) (Work := Work)) :
    RegisterBasis (Input := ActiveKey live) (Phase := VectorOutput Counter)
      (Workspace := Memory (Key := Key) (Counter := Counter) (Work := Work)) :=
  (if active : live original.1 then ⟨original.1, active⟩ else dummy,
    if live original.1 then original.2.1 else 0, ⟨original⟩)

def onRoute (live : Key → Prop) (dummy : ActiveKey live)
    (register : RegisterBasis (Input := ActiveKey live) (Phase := VectorOutput Counter)
      (Workspace := Memory (Key := Key) (Counter := Counter) (Work := Work))) : Prop :=
  register = route live dummy register.2.2.original

def restoreBasis (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live)
    (basis : Basis (ActiveKey live) (VectorOutput Counter) (VectorOutput Counter)
      (Memory (Key := Key) (Counter := Counter) (Work := Work))) :
    Basis Key (VectorOutput Counter) (VectorOutput Counter) Work where
  input := basis.workspace.original.1
  phase := basis.workspace.original.2.1
  workspace := basis.workspace.original.2.2
  database := merge live fixed basis.database

def sparseBasis (live : Key → Prop) (dummy : ActiveKey live)
    (basis : Basis Key (VectorOutput Counter) (VectorOutput Counter) Work) :
    Basis (ActiveKey live) (VectorOutput Counter) (VectorOutput Counter)
      (Memory (Key := Key) (Counter := Counter) (Work := Work)) where
  input := (route live dummy (basisRegisters basis)).1
  phase := (route live dummy (basisRegisters basis)).2.1
  workspace := (route live dummy (basisRegisters basis)).2.2
  database := restrictDatabase live basis.database

@[simp] theorem sparse_basis_on_route (live : Key → Prop) (dummy : ActiveKey live)
    (basis : Basis Key (VectorOutput Counter) (VectorOutput Counter) Work) :
    onRoute live dummy (basisRegisters (sparseBasis live dummy basis)) := by rfl

def restrictFiber (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    SparseState (Counter := Counter) (Work := Work) live :=
  fun basis => if onRoute live dummy (basisRegisters basis) then
    state (restoreBasis live fixed basis) else 0

abbrev FullFiber (live : Key → Prop) (fixed : FixedTable (Counter := Counter) live) :=
  { basis : Basis Key (VectorOutput Counter) (VectorOutput Counter) Work //
    NativePrivateSpendQ58PartitionTransport.onFiber live fixed basis.database }

abbrev SparseFiber (live : Key → Prop) (dummy : ActiveKey live) :=
  { basis : Basis (ActiveKey live) (VectorOutput Counter) (VectorOutput Counter)
      (Memory (Key := Key) (Counter := Counter) (Work := Work)) //
    onRoute live dummy (basisRegisters basis) }

private theorem restore_sparse_basis (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live)
    (basis : FullFiber (Work := Work) live fixed) :
    restoreBasis live fixed (sparseBasis live dummy basis.val) = basis.val := by
  rcases basis with ⟨⟨input, phase, work, database⟩, fiber⟩
  have restored := merge_restrict live fixed database fiber
  change (Basis.mk input phase work
      (merge live fixed (restrictDatabase live database)) :
      Basis Key (VectorOutput Counter) (VectorOutput Counter) Work) =
    Basis.mk input phase work database
  rw [restored]

private theorem sparse_restore_basis (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live)
    (basis : SparseFiber (Counter := Counter) (Work := Work) live dummy) :
    sparseBasis live dummy (restoreBasis live fixed basis.val) = basis.val := by
  rcases basis with ⟨⟨input, phase, memory, database⟩, routed⟩
  change (input, phase, memory) = route live dummy memory.original at routed
  have inputEq := (congrArg Prod.fst routed).symm
  have phaseEq := (congrArg (fun register => register.2.1) routed).symm
  have memoryEq := (congrArg (fun register => register.2.2) routed).symm
  simp only [sparseBasis, restoreBasis, basisRegisters, restrict_merge]
  change (Basis.mk (route live dummy memory.original).1
      (route live dummy memory.original).2.1
      (route live dummy memory.original).2.2 database :
      Basis (ActiveKey live) (VectorOutput Counter) (VectorOutput Counter)
        (Memory (Key := Key) (Counter := Counter) (Work := Work))) =
    Basis.mk input phase memory database
  rw [inputEq, phaseEq, memoryEq]

def fiberEquiv (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live) :
    FullFiber (Work := Work) live fixed ≃ SparseFiber (Counter := Counter) (Work := Work) live dummy where
  toFun basis := ⟨sparseBasis live dummy basis.val, sparse_basis_on_route live dummy basis.val⟩
  invFun basis := ⟨restoreBasis live fixed basis.val,
    merge_on_fiber live fixed basis.val.database⟩
  left_inv basis := Subtype.ext (restore_sparse_basis live dummy fixed basis)
  right_inv basis := Subtype.ext (sparse_restore_basis live dummy fixed basis)

private theorem sum_if_subtype {A : Type} [Fintype A]
    (predicate : A → Prop) (value : A → ℝ) :
    (∑ a, if predicate a then value a else 0) = ∑ a : { x // predicate x }, value a := by
  calc
    _ = ∑ a ∈ (Finset.univ : Finset A).filter predicate, value a := by
      rw [Finset.sum_filter]
    _ = _ := Finset.sum_subtype _ (by simp) value

theorem fixed_fiber_isometry
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (restrictFiber live dummy fixed state) =
      normSquared (NativePrivateSpendQ58PartitionTransport.projectFiber live fixed state) := by
  calc
    _ = ∑ basis : Basis (ActiveKey live) (VectorOutput Counter) (VectorOutput Counter)
        (Memory (Key := Key) (Counter := Counter) (Work := Work)),
        if onRoute live dummy (basisRegisters basis) then
          Complex.normSq (state (restoreBasis live fixed basis)) else 0 := by
      unfold normSquared
      apply Finset.sum_congr rfl
      intro basis _
      by_cases routed : onRoute live dummy (basisRegisters basis) <;>
        simp only [restrictFiber, routed, if_true, if_false, Complex.normSq_zero]
    _ = ∑ basis : SparseFiber (Counter := Counter) (Work := Work) live dummy,
        Complex.normSq (state (restoreBasis live fixed basis.val)) :=
      sum_if_subtype _ _
    _ = ∑ basis : FullFiber (Work := Work) live fixed, Complex.normSq (state basis.val) := by
      rw [← (fiberEquiv live dummy fixed).sum_comp]
      apply Finset.sum_congr rfl
      intro basis _
      exact congrArg (fun full => Complex.normSq (state full))
        (congrArg Subtype.val ((fiberEquiv live dummy fixed).left_inv basis))
    _ = _ := by
      symm
      calc
        _ = ∑ basis : Basis Key (VectorOutput Counter) (VectorOutput Counter) Work,
            if NativePrivateSpendQ58PartitionTransport.onFiber live fixed basis.database then
              Complex.normSq (state basis) else 0 := by
          unfold normSquared
          apply Finset.sum_congr rfl
          intro basis _
          by_cases inside : NativePrivateSpendQ58PartitionTransport.onFiber live fixed basis.database <;>
            simp only [NativePrivateSpendQ58PartitionTransport.projectFiber,
              inside, if_true, if_false, Complex.normSq_zero]
        _ = _ := sum_if_subtype _ _

private theorem restrict_decompress_active
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live) (key : ActiveKey live)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    restrictFiber live dummy fixed (decompressAt key.val state) =
      decompressAt key (restrictFiber live dummy fixed state) := by
  funext target
  by_cases routed : onRoute live dummy (basisRegisters target)
  · change (if onRoute live dummy (basisRegisters target) then
      decompressAt key.val state (restoreBasis live fixed target) else 0) = _
    rw [if_pos routed, decompress_at_eq_sum_kernel, decompress_at_eq_sum_kernel]
    apply Finset.sum_congr rfl
    intro coordinate _
    have stillRouted : onRoute live dummy
        (basisRegisters { target with database := setDatabaseCoordinate target.database key coordinate }) :=
      routed
    simp only [restrictFiber, stillRouted, if_true, restoreBasis, merge_set_active,
      merge_active]
  · change (if onRoute live dummy (basisRegisters target) then
      decompressAt key.val state (restoreBasis live fixed target) else 0) = _
    rw [if_neg routed, decompress_at_eq_sum_kernel]
    symm
    apply Finset.sum_eq_zero
    intro coordinate _
    have offRoute : ¬onRoute live dummy
        (basisRegisters { target with database := setDatabaseCoordinate target.database key coordinate }) :=
      routed
    simp only [restrictFiber, offRoute, if_false, zero_mul]

private theorem restrict_coordinate_active
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live) (key : ActiveKey live)
    (answer : VectorOutput Counter)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    restrictFiber live dummy fixed (coordinateEventProjection key.val answer state) =
      coordinateEventProjection key answer (restrictFiber live dummy fixed state) := by
  funext target
  by_cases routed : onRoute live dummy (basisRegisters target)
  · by_cases read : target.database key = some answer <;>
      simp [restrictFiber, coordinateEventProjection, restoreBasis, routed, merge_active, read]
  · by_cases read : target.database key = some answer <;>
      simp [restrictFiber, coordinateEventProjection, routed, read]

theorem restrict_physical_read_active
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live) (key : ActiveKey live)
    (answer : VectorOutput Counter)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    restrictFiber live dummy fixed (physicalReadBranch key.val answer state) =
      physicalReadBranch key answer (restrictFiber live dummy fixed state) := by
  rw [physical_read_branch_eq_selected, physical_read_branch_eq_selected,
    restrict_decompress_active, restrict_coordinate_active, restrict_decompress_active]

def fullEventProject (live : Key → Prop)
    (event : OriginalRegister (Key := Key) (Counter := Counter) (Work := Work) →
      Database (ActiveKey live) (VectorOutput Counter) → Prop)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :=
  fun basis => if event (basisRegisters basis) (restrictDatabase live basis.database) then
    state basis else 0

def sparseEventProject (live : Key → Prop)
    (event : OriginalRegister (Key := Key) (Counter := Counter) (Work := Work) →
      Database (ActiveKey live) (VectorOutput Counter) → Prop)
    (state : SparseState (Counter := Counter) (Work := Work) live) :=
  fun basis => if event basis.workspace.original basis.database then state basis else 0

theorem event_projection_transport
    (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live)
    (event : OriginalRegister (Key := Key) (Counter := Counter) (Work := Work) →
      Database (ActiveKey live) (VectorOutput Counter) → Prop)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    restrictFiber live dummy fixed (fullEventProject live event state) =
      sparseEventProject live event (restrictFiber live dummy fixed state) := by
  funext basis
  by_cases routed : onRoute live dummy (basisRegisters basis) <;>
    by_cases enabled : event basis.workspace.original basis.database <;>
    simp [restrictFiber, fullEventProject, sparseEventProject, restoreBasis,
      restrict_merge, basisRegisters, enabled]

theorem same_fiber_event_mass
    [Fintype Key] [DecidableEq Key] [Fintype Counter] [DecidableEq Counter]
    [Fintype Work] [DecidableEq Work]
    (live : Key → Prop) (dummy : ActiveKey live)
    (fixed : FixedTable (Counter := Counter) live)
    (event : OriginalRegister (Key := Key) (Counter := Counter) (Work := Work) →
      Database (ActiveKey live) (VectorOutput Counter) → Prop)
    (state : FullState (Key := Key) (Counter := Counter) (Work := Work)) :
    normSquared (sparseEventProject live event (restrictFiber live dummy fixed state)) =
      normSquared (NativePrivateSpendQ58PartitionTransport.projectFiber live fixed
        (fullEventProject live event state)) := by
  rw [← event_projection_transport]
  exact fixed_fiber_isometry live dummy fixed _

theorem sparse_database_contains_only_live_keys
    (live : Key → Prop) (database : Database Key (VectorOutput Counter))
    (key : ActiveKey live) :
    (restrictDatabase live database key).isSome ↔ (database key.val).isSome := Iff.rfl

end
end HegemonCrypto.SmallWood.NativePrivateSpendQ58ActiveEventProjection
