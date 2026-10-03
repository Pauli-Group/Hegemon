# Pinned-source applicability

The local algebra is mapped to clean Binius64 revision
`3f96163049f680b2909f6545690bd929f1b48c44`.

```text
e1737111e915bb865e03cd34bc216fa081891c927c4287db95804ddebd82437f  crates/ip/src/sumcheck/common.rs
85ed45d9a73238f174685dfa6c39c54dd1e40f45fd5b1d74cd91114ec47a7ef3  crates/ip-prover/src/sumcheck/padded.rs
fbad7eacb1256a8b90659c6e6103556e0f6e0149b888e25ec4741a15ad71c6a7  crates/iop/src/basefold/channel.rs
7f1f5204619e0b3ceb7ddbb49a9f463b0bc56248bc59070d1f189f19d04820b0  crates/iop-prover/src/basefold/channel.rs
```

The applicability anchors are narrow:

- `crates/ip/src/sumcheck/common.rs` sends exactly `degree` coefficients and
  reconstructs the omitted highest-degree coefficient from the current sum.
  The strict quadratic kernel therefore keeps this format: send `(c0,c1)` and
  reconstruct `c2=current_claim+c1` in characteristic two.
- `crates/iop*/src/basefold/channel.rs` labels Phase A as a degree-two
  bivariate-product sumcheck.
- `crates/ip-prover/src/sumcheck/padded.rs` explicitly distinguishes genuine
  degree-one padding rounds from degree-two inner rounds. A padding round gets
  only the constant mask `a`; adding `b Z(X)` would violate that degree.

These anchors show where the kernel could fit. They do not implement E384 in
the pinned channels, bind the masks, or prove the outer protocol zero
knowledge.

