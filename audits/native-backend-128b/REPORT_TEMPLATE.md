# Native Backend 128-Bit Review Report Template

Reviewer:

Date:

Repository fingerprint:

Reviewed package hash:

## Summary

- Result:
- Severity:
- Affected claim(s):
- Soundness scope label:
- Reviewed package hash:

## Finding

Describe the issue precisely.

## Reproduction

List exact commands, inputs, or vectors.

- `native-backend-ref verify-vectors ...`
- `native-backend-ref verify-claim --package-dir ...`
- `superneo-bench --verify-review-bundle-production ...`

## Claim Recalculation

- `current_claim.json` agreement/disagreement:
- `attack_model.json` agreement/disagreement:
- `message_class.json` observations:
- `claim_sweep.json` affected rows:
- Reference claim-verifier report:

## Impact

State whether this breaks binding, hiding, soundness, parser safety, canonicality, or timing discipline.

## Suggested Fix

State the concrete fix or claim downgrade.
