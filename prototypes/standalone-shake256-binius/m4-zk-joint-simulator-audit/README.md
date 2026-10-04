# M4 joint-simulator and rank audit

This directory is an executable, source-bound rejection certificate for the coefficient-aware M4 trace-mask patch. It is not a zero-knowledge proof and does not promote a proof-size frontier point.

The audit works over the exact pinned GHASH field

```text
B128 = GF(2)[X]/(X^128 + X^7 + X^2 + X + 1).
```

For a linearized transcript `view = W*witness + R*randomness`, two witnesses induce the same distribution exactly when every column of `W` lies in the column span of `R`. The program checks the equivalent identity `rank(R) = rank([R | W])` with exact B128 Gaussian elimination and also constructs the mask change for arbitrary witness differences.

## Verdict

The frozen patch fails joint simulation before any computational PCS question:

```text
E = m + K
P = a*K
a*E + P = a*m
```

`E` is the inner OTP-encrypted field stream. Outer Spartan later emits the one direct precommit functional `P = <K,T_K>` in the clear. Any nonzero coefficient on a used trace/message key reveals the matching witness functional. BaseFold hiding of the commitment does not erase a separately serialized scalar.

The preferred repair is to delete `P` from the transcript and prove only the grouped wiring relation

```text
<K,T_precommit> + <V,T_private> = batched_sum - public_eval.
```

This restores the clear-linear mask-span condition for every accepted `c != 0`, including the trace key correlation in `M=s+k*c`. It should remove one 16-byte B128 scalar while retaining the same commitments, per-oracle mask inner products, per-oracle reduced evaluations, and combined FRI topology. That byte delta is a source prediction, not a measurement.

The pinned BaseFold implementation cannot express this group yet. Phase A queues and reduces one claim per oracle; only Phase B combines oracles. A real repair needs a cross-oracle relation group, a sum of padded Phase-A provers, the independently masked group claim

```text
(1-gamma)*S + gamma*(sigma_precommit + sigma_private),
```

one reduced `alpha` per member oracle, and an exact verifier mirror. This audit deliberately does not implement that refactor.

An unused precommit blinder `h` is retained as a negative/control design. `P'=a*K+d*h` closes a rank-one clear exposure iff `d != 0`; two independent clear claims require blinder rank two. It is inferior here because it retains the leaking message shape, adds a coordinate/constraint and a nonzero-coefficient sampler, and saves no scalar.

## Run

From the repository root:

```sh
python3 -m unittest discover \
  -s prototypes/standalone-shake256-binius/m4-zk-joint-simulator-audit \
  -p 'test_*.py'

python3 prototypes/standalone-shake256-binius/m4-zk-joint-simulator-audit/joint_simulator_rank_audit.py
```

A successful audit process must still print:

```text
complete_zk=false
current_clear_rank=false
grouped_relation=preferred_conditional_pass
```

The frozen certificate is `certificate.json`; `certificate.schema.json` defines its shape. The validator rejects `complete_zk=true` while source multiplicities, current rank closure, compilation, joint simulation, or QROM composition remain open.

## Inventory boundary

The class inventory covers public context, the precommit and shifted-trace commitments, all inner private/public field streams, the masked trace claim, outer private/Libra commitments and transcript, outer endpoint evaluations, the direct precommit claim, BaseFold mask inner products and masked sumcheck evaluations, FRI fold commitments, terminal data, and Merkle query openings.

Exact multiplicities remain false because the 83-Keccak maximum relation has not been compiled under the 28 GiB disk admission gate. The certificate also keeps these assumptions explicit:

- semantic proof that every `send_public_claim` is genuinely public;
- the grouped-relation implementation and verifier equivalence;
- the full multi-oracle BaseFold/FRI/Merkle simulator, including `gamma=0` and dependent-functional cases;
- outer Libra/Spartan endpoint and dummy-blinding simulation;
- nonlinear composition and selective-failure resistance;
- abort-conditioned ROM/QROM analysis;
- strict mixed B128/E384 PQ128 composition.

Therefore `CompleteZK`, `strict_pq128`, and `frontier_eligible` are all false.
