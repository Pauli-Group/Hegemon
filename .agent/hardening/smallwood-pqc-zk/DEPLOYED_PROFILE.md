# Retained SmallWood V4/Gamma gate

`deployed_strict_profile.py` is the SmallWood-only gate for the protocol that
the repository retains under its historical V4/Gamma identity:
`DirectPacked64CompressedLevel5`, `SMW2`, Goldilocks, and the full SHA-512
Level-5 transcript. No native production route is authorized to select this
profile today. The file names preserve the historical identity; they are not a
deployment claim. This gate is separate from the inactive V5/V6 successor
screens already retained in this directory.

Run it from the repository root with:

    python3 .agent/hardening/smallwood-pqc-zk/deployed_strict_profile.py \
      --profile .agent/hardening/smallwood-pqc-zk/deployed-profile.json \
      --certificate .agent/hardening/smallwood-pqc-zk/deployed-certificate.json \
      --trust-root .agent/hardening/smallwood-pqc-zk/deployed-trust-root.json

The checked-in certificate is intentionally incomplete and exits with status
`2`. It reports `conditional_parameter_pq128 = true`,
`production_soundness_pq128 = false`, `complete_zk = false`, and
`production_authorized = false`. The first result is only the actual-parameter
calculation; it does not authorize production. The checker never reads
capability booleans from the certificate. A verified receipt must be
machine-checked, scoped to the end-to-end protocol, bound to repository
artifacts by SHA-256, and independently listed in the trust root.

The exact interactive terms are derived from the live geometry:

    epsilon_1 = 1 / q^5
    epsilon_2 = 1 / q^5
    epsilon_3 = falling(544, 5) / falling(q - 64, 5)
    epsilon_4 = falling(397, 23) / falling(2^20, 23)

Their aggregate is about `2^-262.3777366`. The conditional ideal-CMS envelope
is about `2^-130.7927741` at a global `2^64` quantum-query budget and
`0.1443083` at `2^128`; these are conditional parameter results, not production
security claims.

The shortest concrete theorem gap is the absent `deployedEndToEnd` constructor
in `formal/crypto/HegemonCrypto/SecurityAuthority.lean`. No theorem currently
turns every accepted compiled Rust proof into modeled verifier evidence and
then composes the SHA-512 QROM instantiation, extraction, and canonical
semantic-refinement facts. Independently, the retained `SMW2` radix-2 DECS
domain has a concrete `23/2^20` witness-recovery event and its leaf grammar
omits index/tape binding, so the current bytes cannot pass the complete-ZK
structural gate even if other receipts are supplied.

The attack record is separate from both calculations. No accepted invalid
transaction proof is recorded. The `SMW2` event above is a concrete privacy
failure, not a soundness forgery. The retained 384-bit Poseidon2 semantic
digest has a generic quantum collision limit near `2^128` queries, but no
end-to-end SmallWood counterfeit has been derived from that component limit.
