# Dashboard requirements and user journeys

This document captures the dashboard actions, operator expectations, and end-to-end journeys requested by maintainers.

## 1. Action inventory

| Slug | Title | Summary | Category |
| --- | --- | --- | --- |
| `dev-setup` | Install toolchains | Run `scripts/dev-setup.sh` to install all CLI dependencies. | Setup & demos |
| `quickstart` | Full workstation quickstart | Sequentially run dev setup, `make check`, `make bench`, and the wallet demo to bootstrap everything. | Setup & demos |
| `wallet-demo` | Wallet demo | Generate throwaway wallet artifacts and inspect a sample shielded transfer. | Setup & demos |
| `fmt` | Format Rust workspace | Execute `cargo fmt --all` for the entire workspace. | Build & test |
| `lint` | Lint with Clippy | Execute workspace-wide `cargo clippy` with warnings treated as errors. | Build & test |
| `test` | Run workspace tests | Run `cargo test --workspace` across all crates. | Build & test |
| `check` | Format, lint, and test | Invoke `make check` which chains fmt, lint, and test. | Build & test |
| `bench-circuits` | Circuit prover benchmark | Run the STARK prover smoke benchmark (`circuits-bench`) with JSON output. | Benchmarks |
| `bench-wallet` | Wallet benchmark | Run the wallet smoke benchmark (`wallet-bench`) with JSON output. | Benchmarks |
| `bench-network` | Network throughput benchmark | Run the Go `netbench` smoke suite from `consensus/bench` with JSON output. | Benchmarks |
| `bench-all` | Full benchmark suite | Execute all prover, wallet, and network benchmarks sequentially via `make bench`. | Benchmarks |

_All action metadata is sourced from `scripts/dashboard.py` and mirrors the workflows explained in README’s “Getting started” and “Operations dashboard” sections._

## 2. Maintainer and operator expectations

### Goals for the CLI experience

- **Consistency with published runbooks.** Operators expect the dashboard to shell out to the exact commands listed in the getting started instructions and runbooks so emergency swaps or security reviews can trust the output without bespoke flags. 【F:README.md†L95-L152】【F:scripts/dashboard.py†L119-L266】
- **Rapid preparedness.** In emergency binding swaps, teams need to confirm validators, wallets, and proofs are all on the same versions. A dashboard run should quickly report success/failure for setup, checks, benchmarks, and wallet demos so operators know when they can move to governance or upgrade actions. 【F:runbooks/emergency_version_swap.md†L3-L46】
- **Evidence capture.** Security testing guidance requires storing the last 50 lines of output and referencing deterministic seeds. Dashboard actions should therefore display command boundaries and elapsed times to simplify copying logs into tickets. 【F:runbooks/security_testing.md†L11-L69】【F:scripts/dashboard.py†L102-L200】

### Anticipated failure cases

- **Toolchain drift or missing dependencies** discovered during `dev-setup` runs, which would block emergency upgrades; dashboard output should highlight failed commands and stop cascading steps. 【F:scripts/dashboard.py†L102-L200】
- **CI parity failures** (fmt/lint/test) that mirror the `make check` workflow; maintainers expect the dashboard to fail fast so regressions cannot slip into release candidates referenced in runbooks. 【F:README.md†L95-L135】【F:scripts/dashboard.py†L158-L200】
- **Benchmark regressions** in prover, wallet, or network components, which operators monitor when preparing for swaps or validating security fixes; any JSON benchmark failure should surface with enough context to triage. 【F:scripts/dashboard.py†L202-L266】【F:runbooks/security_testing.md†L11-L62】
- **Wallet demo issues** encountered when instructing users to upgrade notes (per the emergency swap runbook); missing artifacts or malformed sample transfers are treated as blockers. 【F:runbooks/emergency_version_swap.md†L24-L41】【F:scripts/dashboard.py†L131-L157】

### Success cues

- **Explicit completion banners** (the `Completed '<slug>' in Ns` message) confirming the CLI finished each action without manual inspection. 【F:scripts/dashboard.py†L102-L200】
- **Artifacts ready for review** (e.g., wallet demo outputs, benchmark JSON files, captured logs) that operators can attach to governance proposals or incident tickets. 【F:README.md†L95-L135】【F:runbooks/security_testing.md†L31-L69】
- **Traceable command history** through the dashboard’s printed commands so auditors can reconstruct exactly what ran, matching the documentation requirement in the security runbook. 【F:scripts/dashboard.py†L102-L200】【F:runbooks/security_testing.md†L31-L69】

## 3. User journey map

### Overview

The dashboard needs to support four critical journeys. Each journey lists the trigger (why the operator runs it), required inputs, expected outputs/success cues, and notable edge cases or failure handling expectations.

#### A. Setup (`dev-setup` / `quickstart` stage 1)

- **Trigger:** New workstation provisioning, pre-release validation, or preparing for emergency binding swaps that require patched toolchains. 【F:README.md†L95-L135】【F:runbooks/emergency_version_swap.md†L3-L23】
- **Inputs:** Debian/Ubuntu host with shell access, permission to install Rust, Go, clang-format, jq, and related dependencies. Dashboard must ensure PATH contains cargo/go bins before running subsequent commands. 【F:README.md†L95-L105】【F:scripts/dashboard.py†L20-L86】
- **Outputs / success cues:** Script completes without error, prints completion banner, and leaves toolchains installed (idempotent). Quickstart continues to `make check`. Operators record duration/logs for audit trail. 【F:README.md†L95-L105】【F:scripts/dashboard.py†L102-L157】
- **Edge cases:** Missing package repos or permissions cause early failure; dashboard should stop the quickstart chain and note which command failed so maintainers can unblock before running governance or security playbooks. 【F:scripts/dashboard.py†L102-L157】

#### B. Check (`make check` / `check` action)

- **Trigger:** Ensuring CI-equivalent fmt/lint/test gates pass locally before tagging releases or responding to incidents. 【F:README.md†L95-L135】
- **Inputs:** Rust workspace sources plus toolchains installed; no additional flags. If run via quickstart, inherits environment from setup. 【F:scripts/dashboard.py†L131-L200】
- **Outputs / success cues:** `make check` completes, verifying formatting, linting, and tests. Dashboard prints subcommand boundaries; maintainers can copy logs if CI parity fails. 【F:scripts/dashboard.py†L158-L200】
- **Edge cases:** Long-running tests or Clippy warnings should halt the action; operators expect explicit failure messaging to align with CI runs, avoiding partially-applied upgrades. 【F:scripts/dashboard.py†L102-L200】

#### C. Benchmark suite (`bench-*` actions / `make bench` / quickstart stage 3)

- **Trigger:** Capture baseline metrics before touching hot paths, validating performance after security fixes, or preparing data for governance proposals. 【F:README.md†L95-L135】【F:runbooks/security_testing.md†L11-L69】
- **Inputs:** Compilable workspace plus Go toolchain for netbench; optional JSON log destinations. Dashboard orchestrates each benchmark via the defined commands. 【F:scripts/dashboard.py†L202-L266】
- **Outputs / success cues:** JSON benchmark output for prover, wallet, and network suites; aggregated `bench-all` completion message for reporting. Logs should note command context (working directory) for reproducibility. 【F:scripts/dashboard.py†L202-L285】
- **Edge cases:** Benchmark smoke runs may fail due to resource limits or code regressions. Operators expect the dashboard to stop subsequent benchmarks, highlight the failing component, and allow reruns after fixes. 【F:scripts/dashboard.py†L202-L266】

#### D. Wallet demo (`wallet-demo` / quickstart final stage)

- **Trigger:** Demonstrating sample shielded transfers, verifying upgrade readiness during emergency binding swaps, or giving support teams reproducible wallet artifacts. 【F:README.md†L95-L135】【F:runbooks/emergency_version_swap.md†L24-L41】
- **Inputs:** Previously generated proving/verifying keys (via setup) and disk space for `wallet-demo-artifacts/`. Dashboard passes `--out wallet-demo-artifacts`. 【F:scripts/dashboard.py†L131-L157】
- **Outputs / success cues:** Directory populated with throwaway wallet artifacts plus CLI description of sample transfer; operators archive these when instructing users to upgrade notes. 【F:README.md†L95-L135】【F:scripts/dashboard.py†L131-L157】
- **Edge cases:** Missing artifacts or script failures are treated as blockers for upgrade communications; dashboard should surface errors immediately and avoid deleting partial outputs for forensic review. 【F:runbooks/emergency_version_swap.md†L24-L41】【F:scripts/dashboard.py†L102-L157】
