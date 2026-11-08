# Disposable combined-upgrade fixture

This public Development manifest pins a funded test identity for the opt-in
`combined-upgrade-rehearsal` build. It activates ASERT, mining version rolling
and treasury batching together at height 120. Normal builds do not schedule this
identity or the live pre-mainnet upgrade.

The manifest uses target `0x207fffff` for fast functional tests. It is not an
initial-target or physical-hashpower recommendation. Its miner and funding
address belongs to a fresh disposable local test wallet; no wallet, password,
seed or private key is included. Receiving test rewards requires only this
public address. All acceptance nodes use isolated storage and loopback peers.

Manifest SHA256: `fe959df819c6d2dfcb086eba4d509e5a973155bbc08a10ffee60fd3ec03c7b61`.
Chain ID: `a6ddd1817d8c6987d584214ea5e393cbd0f96d138acc0aa216db4f7618be30f0`.
Genesis: `699b1ae50930ac9f0c37ba9ad3d88804f6300aef21ac16bca6c9196c52688e82`.
