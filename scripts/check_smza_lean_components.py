#!/usr/bin/env python3
"""Portable source/import checker for the RP04/q38 Lean component manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

IMPORT = re.compile(r"^\s*import\s+([A-Za-z0-9_.]+)", re.MULTILINE)
EXTERNAL = ("Mathlib.", "Batteries.", "Std.", "Lean.", "Plausible.", "Cli.", "Qq.", "Aesop.", "Hegemon.", "HegemonCrypto.")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--manifest", type=Path, default=Path(".agent/prod-closure-2026-09-19/release-preparation/PR_CHECKED_LEAN_MANIFEST.json"))
    parser.add_argument("--check-sources", action="store_true", help="validate source hashes and recursive custom imports")
    parser.add_argument("--compile", action="store_true", help="compile serially; opt-in only")
    parser.add_argument("--output-dir", type=Path, help="required explicit output directory with --compile")
    parser.add_argument("--lean", type=Path, default=Path("lean"))
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    manifest_path = args.manifest if args.manifest.is_absolute() else repo / args.manifest
    manifest = json.loads(manifest_path.read_text())
    entries = {item["module"]: item for item in manifest["custom_sources"]}
    if len(entries) != len(manifest["custom_sources"]):
        raise SystemExit("duplicate custom module in manifest")
    for module, item in entries.items():
        path = repo / item["path"]
        if not path.is_file():
            raise SystemExit(f"missing source: {path}")
        actual = sha256(path)
        if actual != item["sha256"]:
            raise SystemExit(f"source hash mismatch: {path}")

    visiting, visited, order, missing = set(), set(), [], []
    def visit(module: str) -> None:
        if module in visited or module in manifest.get("external_modules", []):
            return
        if module in visiting:
            raise SystemExit(f"import cycle at {module}")
        item = entries.get(module)
        if item is None:
            missing.append(module)
            return
        visiting.add(module)
        source = (repo / item["path"]).read_text(errors="strict")
        for imported in IMPORT.findall(source):
            if imported in manifest.get("external_modules", []) or imported.startswith(EXTERNAL):
                continue
            visit(imported)
        visiting.remove(module); visited.add(module); order.append(module)
    for module in manifest["entry_modules"]:
        visit(module)
    if missing:
        raise SystemExit("unresolved custom imports: " + ", ".join(sorted(set(missing))))
    if not args.check_sources and not args.compile:
        args.check_sources = True
    if args.compile:
        if args.output_dir is None or not args.output_dir.is_absolute():
            raise SystemExit("--compile requires an absolute --output-dir")
        args.output_dir.mkdir(parents=True, exist_ok=True)
        # Put fresh outputs first, then existing Lake-built libraries, then
        # inherited configuration and finally pinned source directories.
        # This avoids resolving a just-built custom module from an older cache.
        source_dirs = {repo / root for root in manifest["source_roots"]}
        source_dirs.update((repo / item["path"]).parent for item in entries.values())
        external_dirs = [
            repo / "formal/crypto/.lake/build/lib/lean",
            repo / "formal/lean/.lake/build/lib/lean",
        ]
        external_dirs.extend((repo / "formal/crypto/.lake/packages").glob("*/.lake/build/lib/lean"))
        inherited = [Path(p) for p in os.environ.get("LEAN_PATH", "").split(os.pathsep) if p]
        lean_dirs = [args.output_dir, *external_dirs, *inherited, *sorted(source_dirs)]
        env = dict(os.environ); env["LEAN_PATH"] = os.pathsep.join(str(path) for path in lean_dirs if path.exists())
        for module in order:
            item = entries[module]
            output = args.output_dir / (module.replace(".", "/") + ".olean")
            output.parent.mkdir(parents=True, exist_ok=True)
            command = [str(args.lean), "-j1", "-M2800", "-DwarningAsError=true", "-DautoImplicit=false", "-DmaxHeartbeats=4000000", "-o", str(output), str(repo / item["path"])]
            subprocess.run(command, cwd=repo, env=env, check=True)
    print(json.dumps({"schema": manifest["schema"], "checked_sources": len(visited), "topological_order": order, "compiled": args.compile, "evidence_only": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
