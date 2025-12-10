# STARK Circuit Formal Verification Execution Plan

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

Reference: repository root `.agent/PLANS.md` defines the ExecPlan format and maintenance requirements. Every update to this file must remain consistent with that guidance.

## Purpose / Big Picture

Formally verify the correctness and security of our STARK circuits to provide mathematical guarantees that:

1. **Soundness**: No invalid transaction can produce a valid proof
2. **Completeness**: Every valid transaction can produce a valid proof
3. **Zero-knowledge**: Proofs reveal nothing beyond statement validity
4. **Constraint satisfaction**: AIR constraints correctly encode intended computation

After this work, we have machine-checked proofs that our transaction circuits are correct, eliminating a class of critical bugs that could compromise the entire system.

## Progress

- [ ] Draft plan: capture scope, context, and work breakdown.
- [ ] Select formal verification tools and approach.
- [ ] Create formal specification of transaction validity.
- [ ] Translate AIR constraints to verification framework.
- [ ] Prove constraint soundness and completeness.
- [ ] Verify field arithmetic implementations.
- [ ] Verify Merkle tree operations.
- [ ] Create verification CI pipeline.

## Surprises & Discoveries

- Observation: _None yet._
  Evidence: _Pending implementation._

## Decision Log

- Decision: _None yet._
  Rationale: _Pending implementation._
  Date/Author: _N/A._

## Outcomes & Retrospective

_Pending execution._

## Context and Orientation

Current circuit implementation in `circuits/`:

- `circuits/transaction/src/air.rs` - TransactionCircuitAir with 5-column trace
  - S0, S1, S2: State transition columns
  - merkle_sibling: Merkle path siblings
  - value: Transaction values
  
- `circuits/transaction/src/constraints.rs` - Transition and boundary constraints
  - Value conservation: inputs = outputs + fee
  - Merkle path verification
  - Nullifier derivation
  - Commitment formation

- `circuits/transaction/src/prover.rs` - Trace generation
- `circuits/formal/` - Placeholder for formal specs (currently empty/minimal)

Key dependencies:
- winterfell 0.13.1 - STARK framework
- Goldilocks field (p = 2^64 - 2^32 + 1)
- Blake2-256 for hashing

Properties to verify:
1. **Value conservation**: No inflation/deflation possible
2. **Nullifier uniqueness**: Each note can only be spent once
3. **Commitment binding**: Cannot open commitment to different value
4. **Merkle membership**: Only committed notes can be spent
5. **Authorization**: Only note owner can spend

## Formal Verification Approaches

### Approach A: Interactive Theorem Provers (Coq/Lean)

Use a dependently-typed proof assistant:

**Coq**:
- Mature ecosystem for cryptographic proofs
- Fiat-Crypto library for field arithmetic
- VST for verifying C/Rust code
- Extraction to verified code

**Lean 4**:
- Modern language, faster development
- Mathlib for mathematics
- Growing cryptography libraries
- Better tooling/IDE support

### Approach B: SMT-Based Verification (Z3/CVC5)

Automated verification using SMT solvers:

- Express constraints as SMT formulas
- Automatically check satisfiability
- Find counterexamples if bugs exist
- Good for bounded verification

### Approach C: Domain-Specific Tools

**Ecne** (STARK circuit verification):
- Purpose-built for AIR constraints
- Checks constraint satisfiability
- Relatively new, limited features

**Cairo formal verification tools**:
- StarkWare's verification efforts
- May be adaptable to winterfell

**Circom/SNARK tools**:
- More mature ecosystem
- Would require constraint translation

### Recommended Approach: Hybrid

1. **Lean 4** for high-level proofs (soundness, completeness)
2. **Z3/SMT** for automated constraint checking
3. **Property-based testing** for additional confidence
4. **Fuzzing** for implementation bugs

## Plan of Work

### Phase 1: Formal Specification

1. **Define abstract transaction semantics in Lean 4**
   ```lean
   -- circuits/formal/Transaction.lean
   structure Note where
     value : Nat
     owner : PublicKey
     serial : Nat
   
   structure Transaction where
     inputs : List NoteRef
     outputs : List Note
     fee : Nat
   
   def valid_transaction (tx : Transaction) (state : State) : Prop :=
     -- Sum of input values = sum of output values + fee
     (tx.inputs.map (λ ref => lookup_note state ref).map Note.value).sum
       = (tx.outputs.map Note.value).sum + tx.fee
     -- All input notes exist in state
     ∧ tx.inputs.all (λ ref => note_exists state ref)
     -- No double-spend (nullifiers not in nullifier set)
     ∧ tx.inputs.all (λ ref => nullifier_fresh state (derive_nullifier ref))
     -- ... additional properties
   ```

2. **Define AIR constraint semantics**
   ```lean
   -- circuits/formal/AIR.lean
   structure ExecutionTrace where
     rows : Nat
     cols : Nat
     values : Fin rows → Fin cols → FieldElement
   
   structure AIRConstraints where
     transition : (row_prev row_curr : TraceRow) → Prop
     boundary_first : TraceRow → Prop
     boundary_last : TraceRow → Prop
   
   def trace_satisfies (trace : ExecutionTrace) (air : AIRConstraints) : Prop :=
     -- First row satisfies boundary constraints
     air.boundary_first (trace.row 0)
     -- Last row satisfies boundary constraints
     ∧ air.boundary_last (trace.row (trace.rows - 1))
     -- All consecutive pairs satisfy transition constraints
     ∧ ∀ i : Fin (trace.rows - 1), 
         air.transition (trace.row i) (trace.row (i + 1))
   ```

3. **Specify Goldilocks field operations**
   ```lean
   -- circuits/formal/Field.lean
   def p : Nat := 2^64 - 2^32 + 1  -- Goldilocks prime
   
   structure FieldElement where
     val : Fin p
   
   instance : Add FieldElement where
     add a b := ⟨(a.val + b.val) % p⟩
   
   instance : Mul FieldElement where
     mul a b := ⟨(a.val * b.val) % p⟩
   
   -- Prove field axioms
   theorem add_comm : ∀ a b : FieldElement, a + b = b + a := ...
   theorem mul_assoc : ∀ a b c : FieldElement, (a * b) * c = a * (b * c) := ...
   -- etc.
   ```

### Phase 2: Constraint Translation

1. **Translate Rust AIR to Lean**
   - Create exact correspondence between `air.rs` constraints and Lean specs
   - Document any simplifications or abstractions
   - Maintain bidirectional mapping

2. **Create constraint checker**
   ```lean
   -- circuits/formal/TransactionAIR.lean
   structure TransactionTraceRow where
     s0 : FieldElement
     s1 : FieldElement
     s2 : FieldElement
     merkle_sibling : FieldElement
     value : FieldElement
   
   def transaction_transition 
       (prev curr : TransactionTraceRow) : Prop :=
     -- S0 transition: state accumulator
     curr.s0 = prev.s0 + prev.value
     -- S1 transition: nullifier chain
     ∧ curr.s1 = hash prev.s1 prev.merkle_sibling
     -- ... rest of constraints
   ```

3. **Verify constraint completeness**
   - Every valid transaction has a satisfying trace
   - Prove: `valid_transaction tx state → ∃ trace, trace_satisfies trace transaction_air`

### Phase 3: Soundness Proofs

1. **Prove constraint soundness**
   - Every satisfying trace corresponds to a valid transaction
   - Prove: `trace_satisfies trace transaction_air → valid_transaction (extract_tx trace) state`

2. **Prove value conservation**
   ```lean
   theorem value_conserved :
     ∀ trace : ExecutionTrace,
     trace_satisfies trace transaction_air →
     sum_input_values trace = sum_output_values trace + extract_fee trace
   ```

3. **Prove nullifier derivation**
   ```lean
   theorem nullifier_binding :
     ∀ trace₁ trace₂ : ExecutionTrace,
     trace_satisfies trace₁ transaction_air →
     trace_satisfies trace₂ transaction_air →
     extract_nullifier trace₁ = extract_nullifier trace₂ →
     trace₁.input_note = trace₂.input_note
   ```

4. **Prove commitment binding**
   ```lean
   theorem commitment_binding :
     ∀ cm : Commitment, ∀ v₁ v₂ : Value, ∀ r₁ r₂ : Randomness,
     commit v₁ r₁ = cm →
     commit v₂ r₂ = cm →
     v₁ = v₂
   ```

### Phase 4: Implementation Verification

1. **Verify Rust implementation matches spec**
   - Use `kani` or `verus` for Rust verification
   - Or manual correspondence proofs
   
2. **Verify field arithmetic**
   ```rust
   // Add verification annotations
   #[kani::proof]
   fn goldilocks_mul_comm() {
     let a: u64 = kani::any();
     let b: u64 = kani::any();
     kani::assume(a < GOLDILOCKS_P && b < GOLDILOCKS_P);
     assert_eq!(mul(a, b), mul(b, a));
   }
   ```

3. **Verify trace generation**
   - Prover generates valid traces
   - Traces satisfy AIR constraints

### Phase 5: Automated Checking

1. **SMT constraint encoding**
   ```python
   # circuits/formal/check_constraints.py
   from z3 import *
   
   # Define field elements as bitvectors
   p = 2**64 - 2**32 + 1
   
   def field_add(a, b):
       return (a + b) % p
   
   def field_mul(a, b):
       return (a * b) % p
   
   # Encode transition constraints
   def transaction_transition(prev, curr):
       s0_prev, s1_prev, s2_prev, ms_prev, v_prev = prev
       s0_curr, s1_curr, s2_curr, ms_curr, v_curr = curr
       
       constraints = [
           s0_curr == field_add(s0_prev, v_prev),
           # ... rest of constraints
       ]
       return And(constraints)
   
   # Check for constraint satisfaction
   def check_soundness():
       solver = Solver()
       # Add constraints for invalid transaction
       # Check if SAT (would indicate bug)
   ```

2. **Property-based testing**
   ```rust
   // circuits/transaction/tests/property_tests.rs
   use proptest::prelude::*;
   
   proptest! {
       #[test]
       fn valid_tx_produces_satisfying_trace(
           inputs in valid_inputs_strategy(),
           outputs in valid_outputs_strategy(),
       ) {
           let tx = Transaction::new(inputs, outputs);
           let trace = generate_trace(&tx);
           prop_assert!(verify_constraints(&trace));
       }
       
       #[test]
       fn invalid_tx_no_satisfying_trace(
           tx in invalid_tx_strategy(),
       ) {
           // Should not be able to create valid trace
           let result = try_generate_trace(&tx);
           prop_assert!(result.is_err());
       }
   }
   ```

3. **Fuzzing harness**
   ```rust
   // circuits/transaction/fuzz/fuzz_targets/verify_proof.rs
   #![no_main]
   use libfuzzer_sys::fuzz_target;
   
   fuzz_target!(|data: &[u8]| {
       if let Ok(proof) = StarkProof::from_bytes(data) {
           // Verification should not panic
           let _ = verify(&proof, &random_public_inputs());
       }
   });
   ```

### Phase 6: CI Integration

1. **Verification CI workflow**
   ```yaml
   # .github/workflows/formal-verification.yml
   name: Formal Verification
   
   on:
     push:
       paths:
         - 'circuits/**'
   
   jobs:
     lean-proofs:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: leanprover/lean-action@v1
         - run: lake build
         - run: lake test
     
     smt-checks:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - run: pip install z3-solver
         - run: python circuits/formal/check_constraints.py
     
     property-tests:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - run: cargo test -p transaction-circuit --features proptest
     
     fuzzing:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - run: cargo +nightly fuzz run verify_proof -- -max_total_time=300
   ```

2. **Proof maintenance**
   - Proofs must pass before circuit changes merge
   - Automated proof checking on every PR
   - Version proofs alongside code

## File Structure

```
circuits/
├── formal/
│   ├── lakefile.lean           # Lean build config
│   ├── Formal.lean             # Root import
│   ├── Formal/
│   │   ├── Field.lean          # Goldilocks field
│   │   ├── Hash.lean           # Hash function specs
│   │   ├── Merkle.lean         # Merkle tree specs
│   │   ├── Transaction.lean    # Transaction semantics
│   │   ├── AIR.lean            # AIR framework
│   │   ├── TransactionAIR.lean # Our circuit spec
│   │   ├── Soundness.lean      # Soundness proofs
│   │   └── Completeness.lean   # Completeness proofs
│   ├── smt/
│   │   ├── constraints.smt2    # SMT-LIB constraints
│   │   └── check.py            # SMT checking script
│   └── README.md
├── transaction/
│   ├── tests/
│   │   └── property_tests.rs
│   └── fuzz/
│       └── fuzz_targets/
```

## Security Properties to Verify

### Critical Properties

1. **No inflation**: Cannot create value from nothing
   - Prove: sum(inputs) ≥ sum(outputs) for all valid proofs

2. **No double-spend**: Each nullifier unique per note
   - Prove: nullifier = H(serial || spending_key) is deterministic

3. **Authorization required**: Only key holder can spend
   - Prove: valid signature required in constraints

4. **Merkle membership sound**: Cannot fake membership
   - Prove: Merkle path verification is complete

### Important Properties

5. **Commitment hiding**: Cannot extract value from commitment
   - Model as information-theoretic hiding

6. **Nullifier hiding**: Cannot link nullifier to commitment
   - Model as computational hiding

7. **Fee correctness**: Fees computed correctly
   - Prove: fee = sum(inputs) - sum(outputs)

## Tools and Dependencies

### Primary Tools

- **Lean 4**: Main theorem prover
- **Mathlib4**: Mathematical foundations
- **Z3**: SMT solver for automated checking
- **Proptest**: Property-based testing in Rust
- **cargo-fuzz**: Fuzzing infrastructure

### Optional Tools

- **Kani**: Rust verification (experimental)
- **Verus**: Verified Rust (alternative to Kani)
- **Dafny**: Intermediate verification language

## Success Criteria

1. **Soundness theorem**: Formally proven in Lean 4
2. **Completeness theorem**: Formally proven in Lean 4
3. **Field arithmetic**: All operations verified
4. **SMT checks**: Pass for all constraint encodings
5. **Property tests**: 100K+ cases pass
6. **Fuzzing**: 1M+ executions without crash
7. **CI integration**: All checks run on every PR

## Estimated Timeline

- Phase 1: 5-7 days (Formal Specification)
- Phase 2: 4-5 days (Constraint Translation)
- Phase 3: 7-10 days (Soundness Proofs)
- Phase 4: 5-7 days (Implementation Verification)
- Phase 5: 3-4 days (Automated Checking)
- Phase 6: 2-3 days (CI Integration)

Total: ~26-36 days for comprehensive verification

Note: Timeline assumes familiarity with Lean 4. Add 1-2 weeks for learning curve if needed.

## References

1. "Scalable, transparent, and post-quantum secure computational integrity" - Ben-Sasson et al.
2. "A Verified Algebraic Representation of Cairo Program Execution" - Blockchain Commons
3. Fiat-Crypto: Synthesizing Correct-by-Construction Code for Cryptographic Primitives
4. "Verified Compilation and Optimization of Floating-Point Programs" (methodology)
5. Mathlib documentation for field theory
