# HX512 topology-to-adapter refinement gate

This directory contains an independent, fail-closed checker for the frozen K=1024 BLAKE2b-512 topology and its executable SmallWood adapter.

Current verdict: **not refined**. The frozen grammar and topology pins pass, but no independently replayable adapter certificate exists. The checker does not treat copied topology geometry or a copied shape digest as evidence that the adapter executes the topology.

Run:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-topology-adapter-refinement/check_refinement.py --expect-blocked
PYTHONDONTWRITEBYTECODE=1 python3 -B .agent/hardening/hx512-topology-adapter-refinement/test_refinement.py
```

The retained contract fixes:

- K=1024, maximum degree 6, and zero auxiliary words;
- 95 hash slots and 226 maximum compressions;
- 11,892 hash-base rows, 12,177,408 cells, 2,500 explicit padding cells, and 285,744 operations;
- grammar whole-file SHA-512 `e58ec353612262eb419cc4343d6a72c459d5963616fdd0b52f0619a80afc5eb525552417599f75bea892392a682c6d61839d37e9aba0a9cb864dc190807d986c`, pre-test-support-prefix SHA-512 `b9614b6a9829432dc5e74ff8047d31f3c77131d79e503165d1bd5272ff5aa7d95ffac68005e6b2d2eff27204229cbf3007be83b3152c2a0758e8b10b59f90f6d`, and feature/test-support suffix SHA-512 `ce6d712704e1883b4d68d3c66a2050d05f0fbe8523e8e5547ccfaa1c693a8367449d9f2d7c5f1e4acad6961c4630620277b4b2efb2fbc8ef1166e24435094ccf` at byte 133,958;
- transaction-circuit Cargo manifest SHA-512 `801047eae737ada473fb19248283a125f3ce86dc3b0745521fc3cfc60918193fc2a679e0a992b621b289ea27f901c65388df8803af2bd5e52a65947d76b628c8`;
- topology SHA-512 `a4b7c3e5fcbe43aeac37abf268bdfd7e736ea3e0dcba935595518c3bcbc16b329f6831fc97e92cb36fc2e6c27439b09d49c0ccc052f2968d6fa24afb2897a9a0`.

Canonical call IDs are not execution order. Nullifier call 4 depends on calls 72, 77, or 78 by authorization mode; call 5 depends on 73 or 77. An adapter that compiles `registry.calls` in numeric index order is rejected even though the union dependency graph is acyclic.

The current pre-test-support prefix is a new certified freeze. The previous whole-file hashes were retained, but no byte-for-byte snapshot of either historical production prefix exists, so equality between old and current prefixes is explicitly unproved. The checker makes no stronger historical claim. A fresh topology replay remains mandatory after this 30-case feature seam.

Qualification requires public immutable maps for every topology operation, cell, dependency, source binding, digest target, and padding cell; explicit constant provenance and a disjoint non-hash row range; and 30 two-secret/mode/stable-direction observations covering all 95 calls. The Python checker independently recomputes each retained digest with conventional `hashlib.blake2b`.

`refinement_evidence.json` is never sufficient by itself. A disjoint Rust harness must directly enumerate the live public topology and adapter iterators, normalize and stream-commit every concrete record, reject dropped, duplicated, or unconsumed entries, evaluate every emitted polynomial identity, and bind its RFC observations to the retained artifact. Until that harness is present and invoked in-process, the checker emits `independent_public_iterator_replay_unavailable` even for syntactically perfect JSON.

The deterministic 30-case fixture matrix must be exposed only through the off-by-default `hx512-refinement-evidence` test-support feature (or an equivalent package-owned unit-test hook). Production release checks must reject that feature. The canonical constructor is `hx512_refinement_fixtures()` and each fixture exposes verifier context through `verifier_context()`. The feature supplies synthetic fixtures for all five authorization modes, Disabled/Mint/Burn, and two distinct secret variants; it is not consensus or witness authority.

Those 30 cases cover accepted representative transactions only. Exact authorization refinement additionally requires a grammar-owned, feature-gated 80-case constructor covering all five modes crossed with all sixteen activity masks, followed by live materializer and adapter replay proving exactly 26 accepts and 54 rejects. The existing static `exact_26_accept_54_reject_mode_mask_table` test is useful but cannot substitute for this live cross-implementation classification. That public seam is currently absent, so the checker emits `missing_authorization_mask_replay_api`.

Even a future passing result proves only the hash topology-to-adapter correspondence. Complete transaction semantics, complete zero knowledge, composed PQ/QROM security, proof measurement, verifier/consensus refinement, and production authorization remain separate fail-closed gates.
