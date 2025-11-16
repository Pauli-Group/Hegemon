#!/usr/bin/env python3
"""Project operations dashboard for Synthetic Hegemonic Currency.

This CLI surfaces common development workflows (setup, tests, demos,
and benchmarks) through a single interface so contributors can quickly
run the same commands documented in README.md. The dashboard can be used
interactively, or individual actions can be executed directly via
`--run <slug>`.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
HOME = Path.home()


def _prepend_path(env: Dict[str, str], new_path: Path) -> None:
    if not new_path.exists():
        return
    current = env.get("PATH", "")
    path_parts = current.split(os.pathsep) if current else []
    new_path_str = str(new_path)
    if new_path_str in path_parts:
        return
    if current:
        env["PATH"] = os.pathsep.join([new_path_str] + path_parts)
    else:
        env["PATH"] = new_path_str


def _ensure_toolchain_paths(env: Dict[str, str]) -> None:
    _prepend_path(env, HOME / ".cargo" / "bin")
    _prepend_path(env, HOME / ".local" / "go" / "bin")


@dataclass(frozen=True)
class CommandSpec:
    """Describe a subprocess invocation that belongs to an action."""

    argv: Sequence[str]
    cwd: Path | None = None
    env: Dict[str, str] | None = None


@dataclass(frozen=True)
class DashboardAction:
    """A runbook-ready action that can include multiple commands."""

    slug: str
    title: str
    description: str
    commands: Sequence[CommandSpec]
    category: str
    notes: str | None = None


def _command_to_string(cmd: CommandSpec) -> str:
    readable = shlex.join(cmd.argv)
    extras: list[str] = []
    if cmd.cwd and Path(cmd.cwd) != REPO_ROOT:
        extras.append(f"cwd={cmd.cwd}")
    if cmd.env:
        extras.append(
            "env="
            + ", ".join(f"{key}={value}" for key, value in sorted(cmd.env.items()))
        )
    if extras:
        return f"{readable}  (" + "; ".join(extras) + ")"
    return readable


def prepare_command(cmd: CommandSpec) -> Tuple[List[str], Path, Dict[str, str]]:
    """Return argv/cwd/env for launching a dashboard command."""

    env = os.environ.copy()
    _ensure_toolchain_paths(env)
    if cmd.env:
        env.update(cmd.env)
    cwd = cmd.cwd or REPO_ROOT
    return list(cmd.argv), cwd, env


def _run_command(cmd: CommandSpec) -> tuple[bool, float]:
    argv, cwd, env = prepare_command(cmd)
    start = time.perf_counter()
    try:
        subprocess.run(argv, cwd=cwd, env=env, check=True)
        return True, time.perf_counter() - start
    except subprocess.CalledProcessError as exc:  # pragma: no cover - CLI feedback
        duration = time.perf_counter() - start
        print(
            f"\nCommand failed with exit code {exc.returncode}:"
            f"\n  {_command_to_string(cmd)}",
            file=sys.stderr,
        )
        return False, duration


def run_action(action: DashboardAction) -> bool:
    print(f"\n=== {action.title} ({action.slug}) ===")
    print(textwrap.fill(action.description, width=88))
    if action.notes:
        print("Notes: " + textwrap.fill(action.notes, width=88))
    overall_start = time.perf_counter()
    for cmd in action.commands:
        print(f"\n→ {_command_to_string(cmd)}")
        ok, _ = _run_command(cmd)
        if not ok:
            print("Action aborted due to failure.\n")
            return False
    elapsed = time.perf_counter() - overall_start
    print(f"\nCompleted '{action.slug}' in {elapsed:0.2f}s\n")
    return True


def _actions() -> Dict[str, DashboardAction]:
    return {
        action.slug: action
        for action in [
            DashboardAction(
                slug="dev-setup",
                title="Install toolchains",
                description="Run the repo's development setup script to install toolchains and CLI dependencies.",
                commands=[CommandSpec(["./scripts/dev-setup.sh"], cwd=REPO_ROOT)],
                category="Setup & demos",
            ),
            DashboardAction(
                slug="quickstart",
                title="Full workstation quickstart",
                description="Run dev setup, CI-equivalent checks, benchmarks, and the wallet demo so a new contributor can bootstrap everything in one go.",
                commands=[
                    CommandSpec(["./scripts/dev-setup.sh"], cwd=REPO_ROOT),
                    CommandSpec(["make", "check"], cwd=REPO_ROOT),
                    CommandSpec(["make", "bench"], cwd=REPO_ROOT),
                    CommandSpec(
                        ["./scripts/wallet-demo.sh", "--out", "wallet-demo-artifacts"],
                        cwd=REPO_ROOT,
                    ),
                ],
                category="Setup & demos",
                notes="Equivalent to running dev-setup, make check, make bench, and the wallet demo sequentially.",
            ),
            DashboardAction(
                slug="wallet-demo",
                title="Wallet demo",
                description="Generate throwaway wallet artifacts and inspect a sample shielded transfer.",
                commands=[
                    CommandSpec(
                        ["./scripts/wallet-demo.sh", "--out", "wallet-demo-artifacts"],
                        cwd=REPO_ROOT,
                    )
                ],
                category="Setup & demos",
            ),
            DashboardAction(
                slug="fmt",
                title="Format Rust workspace",
                description="Run `cargo fmt --all` to enforce the canonical Rust style across every crate.",
                commands=[CommandSpec(["cargo", "fmt", "--all"], cwd=REPO_ROOT)],
                category="Build & test",
            ),
            DashboardAction(
                slug="lint",
                title="Lint with Clippy",
                description="Execute `cargo clippy` with workspace-wide targets and fail on warnings.",
                commands=[
                    CommandSpec(
                        [
                            "cargo",
                            "clippy",
                            "--workspace",
                            "--all-targets",
                            "--all-features",
                            "--",
                            "-D",
                            "warnings",
                        ],
                        cwd=REPO_ROOT,
                    )
                ],
                category="Build & test",
            ),
            DashboardAction(
                slug="test",
                title="Run workspace tests",
                description="Execute `cargo test --workspace` for all crates.",
                commands=[CommandSpec(["cargo", "test", "--workspace"], cwd=REPO_ROOT)],
                category="Build & test",
            ),
            DashboardAction(
                slug="check",
                title="Format, lint, and test",
                description="Call `make check` which chains the fmt, lint, and test targets enforced in CI.",
                commands=[CommandSpec(["make", "check"], cwd=REPO_ROOT)],
                category="Build & test",
                notes="This target is equivalent to running the fmt, lint, and test actions sequentially.",
            ),
            DashboardAction(
                slug="bench-circuits",
                title="Circuit prover benchmark",
                description="Run the STARK prover smoke benchmark with JSON output to capture timing baselines.",
                commands=[
                    CommandSpec(
                        [
                            "cargo",
                            "run",
                            "-p",
                            "circuits-bench",
                            "--",
                            "--smoke",
                            "--prove",
                            "--json",
                        ],
                        cwd=REPO_ROOT,
                    )
                ],
                category="Benchmarks",
            ),
            DashboardAction(
                slug="bench-wallet",
                title="Wallet benchmark",
                description="Execute the wallet smoke benchmark to profile note management operations.",
                commands=[
                    CommandSpec(
                        [
                            "cargo",
                            "run",
                            "-p",
                            "wallet-bench",
                            "--",
                            "--smoke",
                            "--json",
                        ],
                        cwd=REPO_ROOT,
                    )
                ],
                category="Benchmarks",
            ),
            DashboardAction(
                slug="bench-network",
                title="Network throughput benchmark",
                description="Run the Go netbench smoke suite under consensus/bench to capture networking KPIs.",
                commands=[
                    CommandSpec(
                        [
                            "go",
                            "run",
                            "./cmd/netbench",
                            "--smoke",
                            "--json",
                        ],
                        cwd=REPO_ROOT / "consensus" / "bench",
                    )
                ],
                category="Benchmarks",
            ),
            DashboardAction(
                slug="bench-all",
                title="Full benchmark suite",
                description="Run the prover, wallet, and network smoke benchmarks sequentially (same as `make bench`).",
                commands=[CommandSpec(["make", "bench"], cwd=REPO_ROOT)],
                category="Benchmarks",
            ),
        ]
    }


def print_action_table(actions: Dict[str, DashboardAction]) -> None:
    print("Available dashboard actions:\n")
    grouped: Dict[str, List[DashboardAction]] = {}
    for action in actions.values():
        grouped.setdefault(action.category, []).append(action)
    for category in sorted(grouped):
        print(category)
        for action in sorted(grouped[category], key=lambda a: a.slug):
            line = f"  {action.slug:<14} {action.title}"
            print(line)
            wrapped = textwrap.wrap(action.description, width=76)
            for wrap_line in wrapped:
                print(f"      {wrap_line}")
            if action.notes:
                for wrap_line in textwrap.wrap("Notes: " + action.notes, width=76):
                    print(f"      {wrap_line}")
        print()


def interactive_loop(actions: Dict[str, DashboardAction]) -> None:
    while True:
        print("\nSynthetic Hegemonic Currency dashboard")
        print("Select an action to run:")
        choices: list[str] = []
        index = 1
        sections: Dict[str, List[DashboardAction]] = {}
        for action in actions.values():
            sections.setdefault(action.category, []).append(action)
        for category in sorted(sections):
            print(f"\n{category}")
            for action in sorted(sections[category], key=lambda a: a.slug):
                print(f"  [{index}] {action.title} ({action.slug})")
                print("      " + textwrap.fill(action.description, width=70))
                choices.append(action.slug)
                index += 1
        print("\n  [L] List actions    [Q] Quit")
        selection = input("Enter choice or slug: ").strip().lower()
        if selection in {"q", "quit", "exit"}:
            print("Goodbye!")
            return
        if selection in {"l", "list"}:
            print()
            print_action_table(actions)
            continue
        # Numeric choices map to slug order.
        if selection.isdigit():
            idx = int(selection) - 1
            if 0 <= idx < len(choices):
                slug = choices[idx]
                run_action(actions[slug])
                continue
        if selection in actions:
            run_action(actions[selection])
        else:
            print("Unrecognized choice. Please try again.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        metavar="SLUG",
        help="Execute a single action non-interactively.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print the available dashboard actions and exit.",
    )
    return parser.parse_args()


def main() -> int:
    os.chdir(REPO_ROOT)
    actions = _actions()
    args = parse_args()
    if args.list:
        print_action_table(actions)
        return 0
    if args.run:
        slug = args.run.strip()
        action = actions.get(slug)
        if not action:
            print(f"Unknown action slug: {slug}", file=sys.stderr)
            return 1
        return 0 if run_action(action) else 1
    interactive_loop(actions)
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
