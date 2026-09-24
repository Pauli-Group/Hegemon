#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hegemon-formal-gate-cli.XXXXXX")"
trap 'rm -rf "$TEST_DIR"' EXIT

expect_rejection() {
  local label="$1"
  local expected_status="$2"
  local expected_text="$3"
  shift 3

  local output
  local status
  if output="$("$@" 2>&1)"; then
    printf '%s unexpectedly succeeded\n' "$label" >&2
    return 1
  else
    status=$?
  fi
  if [ "$status" -ne "$expected_status" ]; then
    printf '%s exited %s, expected %s\n%s\n' \
      "$label" "$status" "$expected_status" "$output" >&2
    return 1
  fi
  if ! printf '%s\n' "$output" | grep -Fq "$expected_text"; then
    printf '%s did not report %q\n%s\n' "$label" "$expected_text" "$output" >&2
    return 1
  fi
}

expect_rejection \
  'formal-core trailing positional argument' \
  2 \
  'usage:' \
  bash "$ROOT/scripts/check_formal_core.sh" checker trailing
expect_rejection \
  'formal-crypto trailing positional argument' \
  2 \
  'usage:' \
  bash "$ROOT/scripts/check_formal_crypto.sh" --isolation-only trailing

mkdir -p "$TEST_DIR/bin" "$TEST_DIR/home"
cat > "$TEST_DIR/bin/cargo" <<'FAKE_CARGO'
#!/usr/bin/env bash
printf '%s\n' \
  'tests::governance_active_gate_evidence_rejects_matrix_mutation: test' \
  'tests::governance_active_goal_rejects_authority_redirection: test' \
  'tests::governance_active_goal_rejects_complete_at_partial_closure: test' \
  'tests::governance_active_goal_rejects_string_only_gate_recipe: test' \
  'tests::governance_blueprint_rejects_claim_authority_mismatch: test' \
  'tests::governance_claims_accept_explicit_tombstone_against_pinned_baseline: test' \
  'tests::governance_claims_reject_coordinated_deletion_without_tombstone: test' \
  'tests::governance_claims_reject_tombstoned_required_conditional_target: test' \
  'tests::governance_claims_reject_unexecuted_gate_record: test' \
  'tests::governance_conditional_authority_cannot_be_marked_production_eligible: test' \
  'tests::governance_conditional_matrix_track_rejects_closed_relabeling: test' \
  'tests::governance_gate_evidence_rejects_incomplete_test_report: test' \
  'tests::governance_gate_evidence_rejects_policy_source_mutations: test'
FAKE_CARGO
chmod +x "$TEST_DIR/bin/cargo"

expect_rejection \
  'formal-core shrunken governance inventory' \
  1 \
  'formal governance test inventory drifted from the pinned 14-test set' \
  env \
    HOME="$TEST_DIR/home" \
    PATH="$TEST_DIR/bin:/usr/bin:/bin" \
    HEGEMON_FORMAL_GATE_SELF_TEST=1 \
    bash "$ROOT/scripts/check_formal_core.sh" checker

printf 'formal gate CLI and governance-inventory negative tests passed\n'
