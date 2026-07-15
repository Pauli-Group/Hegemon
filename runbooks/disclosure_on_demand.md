# Disclosure-on-Demand Status

Targeted payment-proof creation and verification are unavailable in the SmallWood-only release. The retired disclosure proof backend is not linked by `wallet` or `walletd`.

Current behavior:

- `walletd status.get` reports `capabilities.disclosure = false`.
- `wallet payment-proof create|verify` fail closed.
- `walletd` requests `disclosure.create|verify` fail closed.
- `disclosure.list` and `wallet payment-proof purge` remain available for encrypted local outgoing records.

Use offline records or an incoming/full viewing key for a deliberately isolated wallet/account. The shipped keys have no cryptographic account/height scope or revocation, and a local outgoing record is not a cryptographic payment proof.
