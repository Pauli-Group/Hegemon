import HegemonCrypto.NativeLaunchAdaptiveHistoryCodec
import HegemonCrypto.SmallWoodV8Smz9RawCounterCompiler
import SmzaRp05ExecutableMerkleVerifier
import SmzaRp05ExecutableAddressCore

/-!
# One physical raw oracle for both native launch families

This instantiates literal byte routing for the actual SMZB/SMZC profile and
challenge-role frames. Malformed frames, other roles, and counters above the
chosen bound remain live individual raw inputs. A uniform finite raw-query
universe has exactly the pulled-back vector law, and arbitrary coherent raw
queries have a two-query simulation. Family and statement selection may depend
on earlier answers: the source Program replay theorem preserves every read,
including repeats and failed executions, against the same original oracle.

These are input-model and query-simulation theorems. They do not assert a
mixed-family accepted-failure probability, extraction chronology, or privacy.
-/
namespace HegemonCrypto.NativeLaunchAdaptiveHistoryOracle

open scoped Classical ENNReal
open CanonicalBytes
open NativeLaunchAdaptiveHistoryCodec
open SmallWood.V8Smz9RawCounterCompiler
open SmallWood.V8Smz9RuntimeDistribution
open SmallWood.V8Smz9HiddenLeafQrom
open SmallWood.SmzaRp05ExecutableMerkleVerifier (Program)

noncomputable section
set_option autoImplicit false
set_option maxRecDepth 12000
set_option maxHeartbeats 2000000

abbrev PhysicalInput := List CanonicalBytes.Byte

/-- The Rust field-XOF rejects larger requests before making a hash query. -/
def maximumRequestedWords : Nat := 2^24

/-- Source `div_ceil(requested + 32, 8)`, with its explicit zero case. -/
def fieldXofBlocks (requested : Nat) : Nat :=
  if requested = 0 then 0 else (requested + 32 + 7) / 8

/-- Use the source-enforced global bound, without assuming a frontend CSR
maximum has already been refined into Lean. -/
def groupBlockCap : Nat := 2097156

theorem source_maximum_blocks : fieldXofBlocks maximumRequestedWords = groupBlockCap := by
  norm_num [fieldXofBlocks, maximumRequestedWords, groupBlockCap]

theorem source_request_within_group {requested : Nat}
    (within : requested ≤ maximumRequestedWords) :
    fieldXofBlocks requested ≤ groupBlockCap := by
  unfold fieldXofBlocks
  split
  · exact Nat.zero_le _
  · calc
      (requested + 32 + 7) / 8 ≤ (maximumRequestedWords + 32 + 7) / 8 :=
        Nat.div_le_div_right (by omega)
      _ = groupBlockCap := by norm_num [maximumRequestedWords, groupBlockCap]

/-- Concrete candidate request sizes are evidence about the declared source
geometry; the global embedding does not rely on them for completeness. -/
theorem declared_request_block_counts :
    fieldXofBlocks 700 = 92 ∧ fieldXofBlocks 102940 = 12872 ∧
    fieldXofBlocks 5018970 = 627376 ∧ fieldXofBlocks 6 = 5 ∧
    fieldXofBlocks 50 = 11 ∧ fieldXofBlocks 80 = 14 := by
  norm_num [fieldXofBlocks]

theorem group_block_cap_positive : 0 < groupBlockCap := by norm_num [groupBlockCap]
theorem group_block_cap_le_u64 : groupBlockCap ≤ 2^64 := by norm_num [groupBlockCap]

abbrev GroupCounter := Fin groupBlockCap
def groupZero : GroupCounter := ⟨0, group_block_cap_positive⟩

/-- Separate candidate-profile limits for later event routing. The full raw
oracle above is not restricted to these sets. Proving that each accepted
frontend request obeys its declared geometry is a separate source obligation. -/
def declaredProfileRequestedWords : Family → Role → Nat
  | _, .decsMatrix => 700
  | .rp06, .piopMatrix => 102940
  | .htlc, .piopMatrix => 5018970
  | _, .piopOpening => 6
  | .rp06, .decsSample => 50
  | .htlc, .decsSample => 80

def declaredProfileBlocks (family : Family) (role : Role) : Nat :=
  fieldXofBlocks (declaredProfileRequestedWords family role)

theorem declared_profile_blocks_within_group (family : Family) (role : Role) :
    declaredProfileBlocks family role ≤ groupBlockCap := by
  cases family <;> cases role <;>
    norm_num [declaredProfileBlocks, declaredProfileRequestedWords,
      fieldXofBlocks, groupBlockCap]

/-- A per-profile event may select only these coordinates without shrinking
or resampling the common physical oracle or its live complement. -/
def profileCounterRoute (family : Family) (role : Role) :
    Fin (declaredProfileBlocks family role) ↪ GroupCounter where
  toFun counter := ⟨counter.val,
    lt_of_lt_of_le counter.isLt (declared_profile_blocks_within_group family role)⟩
  inj' := by
    intro left right same
    exact Fin.ext (congrArg (fun value : GroupCounter => value.val) same)

theorem profile_counter_route_preserves_counter (family : Family) (role : Role)
    (counter : Fin (declaredProfileBlocks family role)) :
    (profileCounterRoute family role counter).val = counter.val := rfl

def groupEncode (key : CanonicalPrefix × GroupCounter) : PhysicalInput :=
  boundedCounterInput groupBlockCap group_block_cap_le_u64 (encodePrefix key.1, key.2)

theorem group_encode_injective : Function.Injective groupEncode := by
  intro left right equal
  have parts := bounded_counter_input_injective groupBlockCap group_block_cap_le_u64 equal
  exact Prod.ext (encodePrefix_injective (congrArg Prod.fst parts))
    (congrArg (fun pair : PhysicalInput × GroupCounter => pair.2) parts)

abbrev GroupComplement := Complement groupEncode
abbrev GroupKey := CanonicalPrefix ⊕ GroupComplement

def groupAddress : PhysicalInput → GroupKey × GroupCounter :=
  fullRawPaddedCoordinate groupEncode group_encode_injective groupZero

theorem group_address_injective : Function.Injective groupAddress :=
  full_raw_padded_coordinate_injective groupEncode group_encode_injective groupZero

theorem group_address_encode (leading : CanonicalPrefix) (counter : GroupCounter) :
    groupAddress (groupEncode (leading, counter)) = (Sum.inl leading, counter) := by
  simp [groupAddress, fullRawPaddedCoordinate, paddedCoordinate]

theorem profile_route_is_same_physical_address (leading : CanonicalPrefix)
    (counter : Fin (declaredProfileBlocks leading.family leading.role)) :
    groupAddress (groupEncode
      (leading, profileCounterRoute leading.family leading.role counter)) =
      (Sum.inl leading, profileCounterRoute leading.family leading.role counter) :=
  group_address_encode leading _

theorem group_address_complement (input : GroupComplement) :
    groupAddress input.val = (Sum.inr input, groupZero) := by
  simp [groupAddress, fullRawPaddedCoordinate, paddedCoordinate]

/-- Exact full-table factorization retains one common physical oracle; it
does not introduce a separately resampled oracle for each proof or family. -/
def factorOracle {Output : Type*} :
    (PhysicalInput → Output) ≃
      (CanonicalPrefix → GroupCounter → Output) × (GroupComplement → Output) :=
  rawTableFactorization groupEncode group_encode_injective

theorem factor_oracle_source {Output : Type*} (oracle : PhysicalInput → Output)
    (leading : CanonicalPrefix) (counter : GroupCounter) :
    (factorOracle oracle).1 leading counter = oracle (groupEncode (leading, counter)) := rfl

theorem factor_oracle_complement {Output : Type*} (oracle : PhysicalInput → Output)
    (input : GroupComplement) :
    (factorOracle oracle).2 input = oracle input.val := rfl

/-- Concrete finite query universes may contain any mix of the two families,
any metadata/payloads, malformed frames and nonchallenge raw inputs. -/
def finiteKeys (inputs : Finset PhysicalInput) : Finset GroupKey :=
  inputs.image (fun input => (groupAddress input).1)

abbrev FiniteRaw (inputs : Finset PhysicalInput) := { input // input ∈ inputs }
abbrev FiniteKey (inputs : Finset PhysicalInput) := { key // key ∈ finiteKeys inputs }

def finiteAddress (inputs : Finset PhysicalInput) :
    FiniteRaw inputs → FiniteKey inputs × GroupCounter := fun input =>
  (⟨(groupAddress input.val).1,
    Finset.mem_image.mpr ⟨input.val, input.property, rfl⟩⟩,
    (groupAddress input.val).2)

theorem finite_address_injective (inputs : Finset PhysicalInput) :
    Function.Injective (finiteAddress inputs) := by
  intro left right equal
  apply Subtype.ext
  apply group_address_injective
  exact Prod.ext
    (congrArg (fun pair : FiniteKey inputs × GroupCounter => pair.1.val) equal)
    (congrArg (fun pair : FiniteKey inputs × GroupCounter => pair.2) equal)

attribute [local irreducible] groupBlockCap

local instance (inputs : Finset PhysicalInput) : DecidableEq (FiniteKey inputs) :=
  Classical.decEq _
local instance (inputs : Finset PhysicalInput) : DecidableEq (FiniteRaw inputs) :=
  Classical.decEq _
local instance : DecidableEq GroupCounter := Classical.decEq _

/-- A single uniform vector table restricts to the exact uniform raw table,
without any transaction-count or family-count multiplier. This is a law
identity, not a security-loss inequality. -/
theorem one_physical_oracle_uniform_law
    (inputs : Finset PhysicalInput) {Output : Type*}
    [Fintype Output] [Nonempty Output] :
    pmfMap (uniformFintypePMF (FiniteKey inputs → GroupCounter → Output))
      (fun vector input =>
        vector (finiteAddress inputs input).1 (finiteAddress inputs input).2) =
      uniformFintypePMF (FiniteRaw inputs → Output) := by
  exact padded_vector_oracle_has_exact_uniform_raw_law
    (Raw := FiniteRaw inputs) (Key := FiniteKey inputs) (Counter := GroupCounter)
    (Output := Output) (finiteAddress inputs) (finite_address_injective inputs)

/-- The same literal mapping acts correctly on arbitrary query
superpositions and arbitrary workspace, including superposed family tags. -/
theorem one_physical_oracle_coherent_query
    (inputs : Finset PhysicalInput) {Workspace : Type*}
    (vector : FiniteKey inputs → GroupCounter → DigestRegister)
    (state : QueryBasis (FiniteRaw inputs) DigestRegister Workspace → ℂ) :
    twoRoutedVectorQueryLinearEquiv vector (finiteAddress inputs)
      (cleanRoutedVectorState state) =
      cleanRoutedVectorState
        (oracleQueryLinearEquiv
          (fun input => vector (finiteAddress inputs input).1
            (finiteAddress inputs input).2) state) :=
  two_routed_vector_queries_coherent_simulation vector (finiteAddress inputs) state

/-- The finite universe can be computed before all replies of one complete
adaptive source program. Every actual read is covered, including repeats and
aborts. This universe must be chosen for the whole run, not changed after
observing a selected proof or statement. -/
theorem every_adaptive_source_read_has_one_address {Result : Type}
    (oracle : SmallWood.SmzaRp05ExecutableMerkleVerifier.Oracle)
    (program : Program Result)
    (call : SmallWood.V8SmzaOracleParser.RawInput ×
      SmallWood.V8SmzaOracleParser.RawDigest)
    (member : call ∈ (program.record oracle).2) :
    ∃ input : FiniteRaw (SmallWood.SmzaRp05ExecutableAddressCompiler.reachable program),
      input.val = call.1 ∧
      ((finiteAddress _ input).1.val, (finiteAddress _ input).2) =
        groupAddress call.1 := by
  let input : FiniteRaw (SmallWood.SmzaRp05ExecutableAddressCompiler.reachable program) :=
    ⟨call.1, SmallWood.SmzaRp05ExecutableAddressCompiler.recorded_key_reachable
      oracle program call member⟩
  exact ⟨input, rfl, rfl⟩

/-- Reassemble the same physical oracle after factorization. -/
def restoredOracle {Output : Type*} (oracle : PhysicalInput → Output) :
    PhysicalInput → Output := factorOracle.symm (factorOracle oracle)

theorem restored_oracle_eq {Output : Type*} (oracle : PhysicalInput → Output) :
    restoredOracle oracle = oracle := factorOracle.symm_apply_apply oracle

/-- All answer-adaptive source executions retain their outcome and ordered
raw log, including failures and repeated reads. No fixed metadata list or
independent proof-producer assumption occurs. -/
theorem adaptive_source_record_preserved {Result : Type}
    (oracle : SmallWood.SmzaRp05ExecutableMerkleVerifier.Oracle)
    (program : Program Result) :
    program.record (restoredOracle oracle) = program.record oracle := by
  rw [restored_oracle_eq]

end
end HegemonCrypto.NativeLaunchAdaptiveHistoryOracle
