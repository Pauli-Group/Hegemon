#!/usr/bin/env python3
"""Stage and reproduce the four maintained RP05 Lean entry points.

The checked-in generated/Sources tree is a byte-for-byte snapshot of the
reachable project sources.  Mathlib and Lean core remain external dependencies
and are identified by the toolchain/Lake pins plus every external module that
the project closure imports.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from contextlib import contextmanager

REPO = Path(__file__).resolve().parents[1]
PACKAGE = REPO / "formal/rp05"
MANIFEST = PACKAGE / "source-manifest.json"
SOURCE_ROOT = PACKAGE / "generated/Sources"
BUILD_ROOT = PACKAGE / "build"
ALLOWLIST = REPO / ".agent/prod-closure-2026-09-19/release-preparation/RP05_PR_ALLOWLIST.json"
WORK = REPO / ".agent/prod-closure-2026-09-19"
CRITICAL_PINS = {
    ".agent/prod-closure-2026-09-19/privacy-composition/Q38Rp05AdaptiveScheduler.lean":
        "0a3c9fd1f5c6e43be25ce327737c5b129b7665e2c825ac5141e4047c2231f51e",
    ".agent/prod-closure-2026-09-19/privacy-composition/Q38Rp05ActualPivot.lean":
        "d46669ed2c23a8ae5a022ce0b5de0e534165ddbc5af1ca758c4f55220ed48969",
    "formal/rp05/shared/Q38Rp05UniformAverageTransport.lean":
        "cf29911372fb23da9b0b240fffd9a9542fe7f64f74529333411d3e4f6ddbe673",
}
EXPECTED_PUBLIC = {
    "Rp05.Soundness", "Rp05.Privacy", "Rp05.Authorization", "Rp05.Conservation"
}
EXTERNAL_ROOTS = {
    "Aesop", "Batteries", "Cli", "ImportGraph", "Init", "Lake", "Lean",
    "LeanSearchClient", "Mathlib", "Plausible", "ProofWidgets", "Qq", "Std",
}
PUBLIC_ENDPOINTS = {
    "Rp05.Soundness": ("HegemonCrypto.SmallWood.Rp05.soundness",
                       "SmzaRp05CurrentAcceptedSoundnessEndpoint"),
    "Rp05.Privacy": ("HegemonCrypto.SmallWood.Rp05.zero_knowledge",
                      "Q38Rp05ZeroKnowledgeEndpoint"),
    "Rp05.Authorization": ("HegemonCrypto.SmallWood.Rp05.authorization",
                           "SmzaRp05AllActiveHistoricalCredentialEndpoint"),
    "Rp05.Conservation": ("HegemonCrypto.SmallWood.Rp05.conservation",
                           "SmzaRp05CurrentInitializedHistoryConservationEndpoint"),
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def module_path(module: str) -> Path:
    return Path(*module.split(".")).with_suffix(".lean")


def imports(path: Path) -> list[str]:
    found: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.match(r"\s*import\s+(.+?)\s*(?:--.*)?$", line)
        if match:
            found.extend(match.group(1).split())
    return found


def source_index(repo: Path = REPO) -> dict[str, Path]:
    """Match the retained RP05 source resolver's first-root-wins rule."""
    work = repo / ".agent/prod-closure-2026-09-19"
    roots = [
        work,
        repo / ".agent/prod-closure-2026-09-18",
        repo / ".agent/q38-counting-2026-09-18",
        repo / ".agent/q38-counting-2026-09-19",
        repo / "formal/crypto/Hegemon", repo / "formal/crypto/HegemonCrypto",
        repo / "formal/lean/Hegemon", repo / "formal/lean/HegemonCrypto",
        repo / ".agent/artifacts/smallwood-poseidon2-v8-smza/production-closure-2026-09-19",
        repo / ".agent/artifacts/smallwood-poseidon2-v8-smza/production-resume-2026-09-13",
        repo / ".agent/artifacts/smallwood-poseidon2-v8-smza/mathematical-closure-2026-09-14",
        # A few Lean sources are retained under the qualification artifacts
        # rather than the production-closure source root; include only modules
        # reachable through imports from the four public endpoints.
        repo / ".agent/artifacts/smallwood-poseidon2-v8-smza/production-checklist-closure-2026-09-14",
        repo / ".agent/artifacts/smallwood-poseidon2-v8-smza/production-checklist-progress-2026-09-14",
        repo / "formal/rp05/shared",
    ]
    result: dict[str, Path] = {}
    module_roots = (repo / "formal/crypto", repo / "formal/lean")
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.lean")):
            result.setdefault(path.stem, path)
            for module_root in module_roots:
                try:
                    dotted = ".".join(path.relative_to(module_root).with_suffix("").parts)
                except ValueError:
                    continue
                result.setdefault(dotted, path)
    # Maintained package wrappers are roots but are not part of their own
    # dependency closure until those public modules import an endpoint.
    for path in sorted((PACKAGE / "Rp05").glob("*.lean")) if (PACKAGE / "Rp05").exists() else []:
        result[path.stem] = path
        result[".".join(path.relative_to(PACKAGE).with_suffix("").parts)] = path
    return result


def reachable(roots: list[str], index: dict[str, Path],
              allowed_external_roots: set[str] | None = None) -> tuple[dict[str, Path], list[str]]:
    selected: dict[str, Path] = {}
    external: set[str] = set()
    visiting: set[str] = set()

    def visit(module: str) -> None:
        if module in selected:
            return
        if module in visiting:
            raise RuntimeError(f"Lean import cycle at {module}")
        path = index.get(module)
        if path is None:
            if allowed_external_roots is not None and not any(
                    module == root or module.startswith(root + ".")
                    for root in allowed_external_roots):
                raise RuntimeError(f"unresolved non-core/non-Mathlib import: {module}")
            external.add(module)
            return
        visiting.add(module)
        for dependency in imports(path):
            if dependency in visiting:
                raise RuntimeError(f"Lean import cycle: {module} imports active {dependency}")
            visit(dependency)
        visiting.remove(module)
        selected[module] = path

    for root in roots:
        visit(root)
    return selected, sorted(external)


def public_roots_from_allowlist() -> tuple[list[str], dict[str, str]]:
    if not ALLOWLIST.is_file():
        raise RuntimeError(f"retained allowlist not found: {ALLOWLIST}")
    data = json.loads(ALLOWLIST.read_text())
    roots = [data["endpoints"][key]["module"] for key in ("S", "P", "A", "C")]
    endpoint_pins = {data["endpoints"][key]["source"]: data["endpoints"][key]["source_sha256"]
                     for key in ("S", "P", "A", "C")}
    for rel, digest in CRITICAL_PINS.items():
        endpoint_pins[rel] = digest
    return roots, endpoint_pins


def stage() -> None:
    """Create the reviewable, checked-in source snapshot from retained paths."""
    endpoint_roots, pins = public_roots_from_allowlist()
    wrapper_paths = sorted((PACKAGE / "Rp05").glob("*.lean"))
    if {"Rp05." + p.stem for p in wrapper_paths} != EXPECTED_PUBLIC:
        raise RuntimeError("expected all four maintained Rp05 public entry modules before staging")
    roots = ["Rp05." + path.stem for path in wrapper_paths]
    index = source_index()
    selected, external = reachable(roots, index, EXTERNAL_ROOTS)
    missing_roots = set(endpoint_roots) - set(index)
    if missing_roots:
        raise RuntimeError(f"retained endpoint sources missing from resolver: {sorted(missing_roots)}")
    # Endpoints are included by wrappers, but validate their exact source pins.
    for rel, expected in pins.items():
        path = REPO / rel
        if not path.is_file() or sha256_file(path) != expected:
            raise RuntimeError(f"pinned source mismatch: {rel}")
    for module in sorted(EXPECTED_PUBLIC):
        if module not in selected:
            raise RuntimeError(f"public entry point is outside the staged source graph: {module}")
    if not selected:
        raise RuntimeError("empty RP05 source graph")

    staged_records = []
    staging_root = PACKAGE / "generated/.Sources.staging"
    if staging_root.exists():
        shutil.rmtree(staging_root)
    for module, source in sorted(selected.items()):
        content = source.read_bytes()
        staged = staging_root / module_path(module)
        staged.parent.mkdir(parents=True, exist_ok=True)
        staged.write_bytes(content)
        staged_records.append({
            "module": module,
            "source": source.relative_to(REPO).as_posix(),
            "staged": (Path("generated/Sources") / module_path(module)).as_posix(),
            "sha256": sha256_bytes(content),
        })
    # Record the exact external object boundary exposed by the pinned Lake
    # environment. Those objects are not copied into the project source tree.
    _, lake_path, _ = lake_environment()
    external_roots = resolved_lake_paths(lake_path)
    external_objects = []
    for module in external:
        obj = locate_object(module, external_roots)
        if obj is None:
            raise RuntimeError(f"external import has no OLean in the Lake environment: {module}")
        try:
            origin = {"root": external_roots.index(next(root for root in external_roots
                                                        if obj.is_relative_to(root))),
                      "relative_path": obj.relative_to(next(root for root in external_roots
                                                              if obj.is_relative_to(root))).as_posix()}
        except (StopIteration, ValueError):
            origin = {"root": -1, "relative_path": obj.name}
        external_objects.append({"module": module, "olean_sha256": sha256_file(obj), **origin})
    manifest = {
        "schema": "hegemon.rp05.proof-package.sources.v1",
        "purpose": "Reachability-closed source snapshot for the four maintained RP05 theorem entry points; not a production authorization.",
        "retained_allowlist": {
            "path": ALLOWLIST.relative_to(REPO).as_posix(),
            "sha256": sha256_file(ALLOWLIST),
        },
        "source_resolution_policy": "The source index follows the retained resolver's ordered roots and first-root-wins rule, then adds the qualification closure/progress source roots for project modules whose retained compile receipts otherwise name only passed OLean objects; each selected module path and byte hash is recorded below.",
        "toolchain": {
            "lean_toolchain_path": "formal/crypto/lean-toolchain",
            "lean_toolchain_sha256": sha256_file(REPO / "formal/crypto/lean-toolchain"),
            "lakefile_path": "formal/crypto/lakefile.toml",
            "lakefile_sha256": sha256_file(REPO / "formal/crypto/lakefile.toml"),
            "lake_manifest_path": "formal/crypto/lake-manifest.json",
            "lake_manifest_sha256": sha256_file(REPO / "formal/crypto/lake-manifest.json"),
        },
        "public_roots": [{"module": module, "theorem": theorem, "endpoint_module": endpoint}
                         for module, (theorem, endpoint) in PUBLIC_ENDPOINTS.items()],
        "endpoint_source_pins": [{"path": k, "sha256": v} for k, v in sorted(pins.items())],
        "sources": staged_records,
        "external_imports": external,
        "external_objects": external_objects,
        "counts": {"source_modules": len(staged_records), "external_imports": len(external)},
    }
    manifest_tmp = MANIFEST.with_suffix(".json.tmp")
    manifest_tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    # Replace only the owned generated source directory. Build the new tree
    # first so an interrupted refresh leaves the previous snapshot untouched.
    old_root = PACKAGE / "generated/.Sources.previous"
    if old_root.exists():
        shutil.rmtree(old_root)
    if SOURCE_ROOT.exists():
        SOURCE_ROOT.rename(old_root)
    staging_root.rename(SOURCE_ROOT)
    old_root_removed = False
    try:
        os.replace(manifest_tmp, MANIFEST)
        old_root_removed = True
    finally:
        if old_root_removed and old_root.exists():
            shutil.rmtree(old_root)
        elif old_root.exists() and not SOURCE_ROOT.exists():
            old_root.rename(SOURCE_ROOT)
        manifest_tmp.unlink(missing_ok=True)
    print(f"staged {len(staged_records)} Lean modules; {len(external)} external imports")


def load_manifest() -> dict:
    if not MANIFEST.is_file():
        raise RuntimeError(f"missing source manifest: {MANIFEST}")
    manifest = json.loads(MANIFEST.read_text())
    if manifest.get("schema") != "hegemon.rp05.proof-package.sources.v1":
        raise RuntimeError("unsupported source manifest schema")
    return manifest


def checked_graph(manifest: dict) -> tuple[dict[str, Path], dict[str, str]]:
    graph: dict[str, Path] = {}
    expected_hash: dict[str, str] = {}
    for record in manifest["sources"]:
        module, path, digest = record["module"], PACKAGE / record["staged"], record["sha256"]
        if module in graph:
            raise RuntimeError(f"duplicate source module: {module}")
        if not path.is_file():
            raise RuntimeError(f"missing staged source: {record['staged']}")
        actual = sha256_file(path)
        if actual != digest:
            raise RuntimeError(f"source hash mismatch for {module}: expected {digest}, got {actual}")
        graph[module] = path
        expected_hash[module] = digest
    expected_paths = {Path(record["staged"]).as_posix() for record in manifest["sources"]}
    actual_paths = {path.relative_to(PACKAGE).as_posix() for path in SOURCE_ROOT.rglob("*.lean")}
    if actual_paths != expected_paths:
        raise RuntimeError("generated source tree contains missing or unmanifested Lean files")
    return graph, expected_hash


def validate_source_pins(manifest: dict) -> None:
    source_by_path = {record["source"]: record for record in manifest["sources"]}
    for pin in manifest["endpoint_source_pins"]:
        record = source_by_path.get(pin["path"])
        if record is None or record["sha256"] != pin["sha256"]:
            raise RuntimeError(f"endpoint or approved helper pin is missing: {pin['path']}")


def cache_state_matches(entry: dict, source_hash: str, imports_now: dict[str, str],
                        lean_version: str, lean_hash: str, olean_hash: str) -> bool:
    return (entry.get("source_sha256") == source_hash
            and entry.get("imports") == imports_now
            and entry.get("lean_version") == lean_version
            and entry.get("lean_sha256") == lean_hash
            and entry.get("olean_sha256") == olean_hash)


def verify_sources() -> dict:
    manifest = load_manifest()
    graph, _ = checked_graph(manifest)
    validate_source_pins(manifest)
    for path_key, hash_key in (("lean_toolchain_path", "lean_toolchain_sha256"),
                               ("lakefile_path", "lakefile_sha256"),
                               ("lake_manifest_path", "lake_manifest_sha256")):
        pinned_path = REPO / manifest["toolchain"][path_key]
        if not pinned_path.is_file() or sha256_file(pinned_path) != manifest["toolchain"][hash_key]:
            raise RuntimeError(f"toolchain/Lake input pin changed: {manifest['toolchain'][path_key]}")
    expected_modules = set(graph)
    public_roots = [entry["module"] for entry in manifest["public_roots"]]
    selected, _ = reachable(public_roots, graph, EXTERNAL_ROOTS)
    if set(selected) != expected_modules:
        raise RuntimeError("manifest source set is not exactly the four-root import closure")
    external: set[str] = set()
    for module, path in graph.items():
        for dependency in imports(path):
            if dependency not in expected_modules:
                if not any(dependency == root or dependency.startswith(root + ".")
                           for root in EXTERNAL_ROOTS):
                    raise RuntimeError(f"non-core/non-Mathlib import is unresolved: {dependency}")
                external.add(dependency)
    if sorted(external) != manifest["external_imports"]:
        raise RuntimeError("external import boundary differs from the pinned manifest")
    _, lake_path, _ = lake_environment()
    roots = resolved_lake_paths(lake_path)
    if len(manifest["external_objects"]) != len(external):
        raise RuntimeError("external OLean boundary is incomplete")
    for expected in manifest["external_objects"]:
        module = expected["module"]
        # Lake supplies the locked Mathlib/Core libraries; source modules from
        # this package take precedence in the generated tree.
        obj = locate_object(module, roots)
        actual_root = next((i for i, root in enumerate(roots)
                            if obj is not None and obj.is_relative_to(root)), None)
        actual_rel = (obj.relative_to(roots[actual_root]).as_posix()
                      if obj is not None and actual_root is not None else None)
        if (obj is None or sha256_file(obj) != expected["olean_sha256"]
                or actual_root != expected["root"] or actual_rel != expected["relative_path"]):
            raise RuntimeError(f"external object boundary changed for {module}")
    public_modules = {entry["module"] for entry in manifest["public_roots"]}
    if public_modules != EXPECTED_PUBLIC or not public_modules.issubset(expected_modules):
        raise RuntimeError("public root set is incomplete or unexpected")
    for module in public_modules:
        theorem, expected_endpoint = PUBLIC_ENDPOINTS[module]
        entry = next(item for item in manifest["public_roots"] if item["module"] == module)
        if (entry.get("theorem") != theorem or entry.get("endpoint_module") != expected_endpoint):
            raise RuntimeError(f"public theorem contract changed for {module}")
        wrappers = imports(graph[module])
        if wrappers != [expected_endpoint]:
            raise RuntimeError(f"public wrapper {module} must import only {expected_endpoint}")
    print(f"PASS source closure: {len(graph)} modules, {len(external)} external imports, 4 public roots")
    return manifest


def lake_environment() -> tuple[str, str, str]:
    cwd = REPO / "formal/crypto"
    def lake_printenv(name: str) -> str:
        result = subprocess.run(["lake", "env", "printenv", name], cwd=cwd,
                                text=True, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError(f"lake env printenv {name} failed: {result.stderr.strip()}")
        return result.stdout.strip()
    path = lake_printenv("PATH")
    lean_path = lake_printenv("LEAN_PATH")
    lean = shutil.which("lean", path=path)
    if not lean:
        raise RuntimeError("Lean executable is not present in `lake env PATH`")
    version = subprocess.run([lean, "--version"], cwd=cwd, text=True,
                             capture_output=True, check=False)
    if version.returncode:
        raise RuntimeError(version.stderr.strip())
    return lean, lean_path, version.stdout.strip()


def resolved_lake_paths(lake_path: str) -> list[Path]:
    cwd = REPO / "formal/crypto"
    result = []
    for raw in lake_path.split(os.pathsep):
        if not raw:
            continue
        path = Path(raw)
        result.append(path.resolve() if path.is_absolute() else (cwd / path).resolve())
    return result


def topological(graph: dict[str, Path], roots: list[str]) -> list[str]:
    result: list[str] = []
    done: set[str] = set()
    active: set[str] = set()
    def visit(module: str) -> None:
        if module in done:
            return
        if module in active:
            raise RuntimeError(f"Lean import cycle at {module}")
        if module not in graph:
            raise RuntimeError(f"missing internal source for {module}")
        active.add(module)
        for dependency in imports(graph[module]):
            if dependency in graph:
                visit(dependency)
        active.remove(module)
        done.add(module)
        result.append(module)
    for root in roots:
        visit(root)
    return result


def locate_object(module: str, search: list[Path]) -> Path | None:
    rel = module_path(module).with_suffix(".olean")
    for root in search:
        candidate = root / rel
        if candidate.is_file():
            return candidate
    return None


STRICT_LEAN_FLAGS = ["-j1", "-M16384", "-DElab.async=false",
                     "-DwarningAsError=true", "-DautoImplicit=false",
                     "-DmaxHeartbeats=40000000", "-DstderrAsMessages=false"]
LAKE_FORMAL_PREFIXES = ("formal/crypto/", "formal/lean/")
LAKE_FORMAL_COUNT = 257


def retained_memory_budget_valid(argv: list[str]) -> bool:
    budgets: list[int] = []
    for index, argument in enumerate(argv):
        if argument == "-M" and index + 1 < len(argv) and argv[index + 1].isdigit():
            budgets.append(int(argv[index + 1]))
        elif argument.startswith("-M") and argument[2:].isdigit():
            budgets.append(int(argument[2:]))
    return len(budgets) == 1 and 0 < budgets[0] <= 16384


def retained_receipts() -> dict[str, list[dict]]:
    result: dict[str, list[dict]] = {}
    receipt_root = WORK / "current-compiler/receipts"
    for receipt_path in sorted(receipt_root.glob("*.dag.json")):
        try:
            receipt = json.loads(receipt_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        module = receipt.get("module")
        if isinstance(module, str):
            result.setdefault(module, []).append(receipt)
    return result


def lake_formal_records(manifest: dict) -> dict[str, dict]:
    records = {record["module"]: record for record in manifest["sources"]
               if record.get("source", "").startswith(LAKE_FORMAL_PREFIXES)}
    if len(records) != LAKE_FORMAL_COUNT:
        raise RuntimeError(f"expected exactly {LAKE_FORMAL_COUNT} original formal sources for Lake adoption")
    for module, record in records.items():
        source = Path(record["source"])
        prefix = next(prefix for prefix in LAKE_FORMAL_PREFIXES
                      if record["source"].startswith(prefix))
        if source.as_posix() != (Path(prefix) / module_path(module)).as_posix():
            raise RuntimeError(f"Lake source path does not match module {module}")
    return records


def lake_object_path(module: str, source_record: dict) -> Path | None:
    source = source_record["source"]
    if source.startswith("formal/crypto/"):
        root = REPO / "formal/crypto/.lake/build/lib/lean"
    elif source.startswith("formal/lean/"):
        root = REPO / "formal/lean/.lake/build/lib/lean"
    else:
        return None
    target = root / module_path(module).with_suffix(".olean")
    if not target.is_file() or not target.resolve().is_relative_to(root.resolve()):
        return None
    return target


def _lake_trace_pairs(value) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if isinstance(value, list):
        if len(value) == 2 and isinstance(value[0], str) and isinstance(value[1], str):
            pairs.append((value[0], value[1]))
        for child in value:
            pairs.extend(_lake_trace_pairs(child))
    elif isinstance(value, dict):
        for child in value.values():
            pairs.extend(_lake_trace_pairs(child))
    return pairs


def _lake_trace_option_record(inputs) -> dict | None:
    """Preserve either Lake's explicit options or its opaque default-options hash."""
    entries = [item for item in inputs
               if isinstance(item, list) and len(item) == 2 and item[0] == "options"]
    if len(entries) != 1:
        return None
    value = entries[0][1]
    if isinstance(value, str):
        if not re.fullmatch(r"[0-9a-f]{16}", value):
            return None
        form = "opaque-default-options-hash"
    elif isinstance(value, list) and value:
        if any(not isinstance(item, list) or len(item) != 2
               or not isinstance(item[0], str)
               or not isinstance(item[1], str)
               or not re.fullmatch(r"[0-9a-f]{16}", item[1])
               for item in value):
            return None
        form = "explicit-option-hashes"
    else:
        return None
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return {"form": form, "value": value, "sha256": sha256_bytes(encoded.encode())}


def lake_trace_path_matches(message: str, lake_path: str, lean: str) -> bool:
    match = re.search(r"(?:^|\s)LEAN_PATH=([^\s]+)", message)
    if match is None:
        return False
    expected = [Path(part).resolve() for part in lake_path.split(os.pathsep) if part]
    actual = [Path(part).resolve() for part in match.group(1).split(os.pathsep) if part]
    core_root = (Path(lean).resolve().parents[1] / "lib/lean").resolve()
    if not expected or expected[-1] != core_root:
        return False
    # Lean adds the pinned toolchain's core library implicitly, so Lake's saved
    # command may omit only that final LEAN_PATH component.
    return actual == expected or actual == expected[:-1]


def lake_trace_paths_for_source(source: Path, lake_path: str, lean: str) -> list[str]:
    expected = [lake_path]
    formal_lean_root = (REPO / "formal/lean/.lake/build/lib/lean").resolve()
    if source.resolve().is_relative_to((REPO / "formal/lean").resolve()):
        core_root = (Path(lean).resolve().parents[1] / "lib/lean").resolve()
        standalone_path = os.pathsep.join((str(formal_lean_root), str(core_root)))
        if standalone_path not in expected:
            expected.append(standalone_path)
    return expected


def lake_trace_pins(module: str, source: Path, target: Path, lean: str,
                    lean_version: str, lake_path: str) -> dict | None:
    trace_path = target.with_suffix(".trace")
    try:
        trace_bytes = trace_path.read_bytes()
        trace = json.loads(trace_bytes)
    except (OSError, json.JSONDecodeError):
        return None
    outputs = trace.get("outputs", {}).get("o")
    if (trace.get("synthetic") is not False or not isinstance(outputs, list)
            or len(outputs) != 1 or not isinstance(outputs[0], str)
            or not re.fullmatch(r"[0-9a-f]+\.olean", outputs[0])):
        return None
    pairs = _lake_trace_pairs(trace.get("inputs", []))
    source_inputs = [digest for name, digest in pairs if name == str(source.resolve())]
    module_inputs = [digest for name, digest in pairs
                     if name == f"Module.name: {module}"]
    version_match = re.search(r"\(version ([^,]+),.*?commit ([0-9a-f]+)", lean_version)
    if version_match is None:
        return None
    expected_lean_input = f"Lean {version_match.group(1)}, commit {version_match.group(2)[:7]}"
    lean_inputs = [digest for name, digest in pairs if name.startswith(expected_lean_input)]
    option_record = _lake_trace_option_record(trace.get("inputs", []))
    if (len(source_inputs) != 1 or len(module_inputs) != 1 or len(lean_inputs) != 1
            or any(not re.fullmatch(r"[0-9a-f]{16}", digest)
                   for digest in (source_inputs[0], module_inputs[0], lean_inputs[0]))
            or option_record is None):
        return None
    logs = [entry.get("message", "") for entry in trace.get("log", [])
            if isinstance(entry, dict)]
    expected_lake_paths = lake_trace_paths_for_source(source, lake_path, lean)
    if not any(str(lean) in message and str(source.resolve()) in message
               and f"-o {target}" in message
               and any(lake_trace_path_matches(message, expected, lean)
                       for expected in expected_lake_paths)
               for message in logs):
        return None
    return {
        "sha256": sha256_bytes(trace_bytes),
        "schema_version": trace.get("schemaVersion"),
        "lake_output_pin": outputs[0],
        "lake_source_input_pin": source_inputs[0],
        "lake_module_input_pin": module_inputs[0],
        "lake_compiler_input_pin": lean_inputs[0],
        "lake_options": option_record,
    }


def lake_candidate_snapshot(module: str, record: dict, graph: dict[str, Path],
                            formal_records: dict[str, dict], external_roots: list[Path],
                            lean: str, lean_version: str, lake_path: str,
                            environment: dict) -> dict | None:
    source = REPO / record["source"]
    staged = graph[module]
    target = lake_object_path(module, record)
    if target is None or not source.is_file() or not staged.is_file():
        return None
    expected_hash = record["sha256"]
    if (sha256_file(source) != expected_hash or sha256_file(staged) != expected_hash):
        return None
    imports_now: dict[str, str] = {}
    for dependency in imports(staged):
        if dependency in formal_records:
            dependency_object = lake_object_path(dependency, formal_records[dependency])
        elif dependency in graph:
            # Do not mix canonical Lake objects with relocated project objects.
            return None
        else:
            dependency_object = locate_object(dependency, external_roots)
        if dependency_object is None:
            return None
        imports_now[dependency] = sha256_file(dependency_object)
    trace = lake_trace_pins(module, source, target, lean, lean_version, lake_path)
    if trace is None:
        return None
    return {
        "source_sha256": sha256_file(source),
        "staged_sha256": sha256_file(staged),
        "imports": imports_now,
        "environment": environment,
        "olean_sha256": sha256_file(target),
        "trace": trace,
        "trace_sha256": trace["sha256"],
        "lake_object": str(target.resolve()),
    }


def lake_rehash_groups(modules: list[str], lake: str) -> dict[str, dict]:
    """Validate Lake target groups without building; bisect only failed groups."""
    validated: dict[str, dict] = {}
    cwd = REPO / "formal/crypto"

    def check_group(group: list[str]) -> None:
        if not group:
            return
        command = [lake, "--rehash", "--no-build", "--no-cache", "build",
                   *(f"+{module}:olean" for module in group)]
        try:
            result = subprocess.run(command, cwd=cwd, text=True, capture_output=True,
                                    check=False, timeout=1800)
        except (OSError, subprocess.TimeoutExpired):
            return
        if result.returncode == 0:
            entry = {"argv": command, "exit_code": 0,
                     "stdout_sha256": sha256_bytes(result.stdout.encode()),
                     "stderr_sha256": sha256_bytes(result.stderr.encode()),
                     "targets": list(group)}
            for module in group:
                validated[module] = entry
        elif len(group) > 1:
            middle = len(group) // 2
            check_group(group[:middle])
            check_group(group[middle:])

    check_group(modules)
    return validated


def validate_lake_originals(manifest: dict, graph: dict[str, Path],
                            external_roots: list[Path], lean: str,
                            lean_version: str, lake_path: str) -> dict[str, dict]:
    """Return only unchanged original Lake objects accepted by no-build rehash."""
    formal_records = lake_formal_records(manifest)
    lake = shutil.which("lake")
    if not lake:
        return {}
    lake = str(Path(lake).absolute())
    cwd = REPO / "formal/crypto"
    def environment_snapshot() -> dict | None:
        lake_version_result = subprocess.run([lake, "--version"], cwd=cwd,
                                             text=True, capture_output=True, check=False)
        lean_version_result = subprocess.run([lean, "--version"], cwd=cwd,
                                             text=True, capture_output=True, check=False)
        if (lake_version_result.returncode != 0 or lean_version_result.returncode != 0
                or lean_version_result.stdout.strip() != lean_version
                or "(Lean version " + lean_version.split("version ", 1)[-1].split(",", 1)[0] + ")"
                not in lake_version_result.stdout):
            return None
        toolchain_inputs = {}
        for path_key, hash_key in (("lean_toolchain_path", "lean_toolchain_sha256"),
                                   ("lakefile_path", "lakefile_sha256"),
                                   ("lake_manifest_path", "lake_manifest_sha256")):
            path = REPO / manifest["toolchain"][path_key]
            digest = sha256_file(path) if path.is_file() else ""
            if digest != manifest["toolchain"][hash_key]:
                return None
            toolchain_inputs[path_key] = digest
        return {
            "lean": str(Path(lean).resolve()),
            "lean_sha256": sha256_file(Path(lean)),
            "lean_version": lean_version,
            "lake": lake,
            "lake_sha256": sha256_file(Path(lake)),
            "lake_version": lake_version_result.stdout.strip(),
            "lake_path": lake_path,
            "toolchain_inputs": toolchain_inputs,
        }

    environment = environment_snapshot()
    if environment is None:
        return {}
    lake_version = environment["lake_version"]
    pre = {module: lake_candidate_snapshot(module, record, graph, formal_records,
                                           external_roots, lean, lean_version,
                                           lake_path, environment)
           for module, record in formal_records.items()}
    groups: dict[str, list[str]] = {"formal/crypto/": [], "formal/lean/": []}
    for module, record in formal_records.items():
        if pre[module] is not None:
            root = next(prefix for prefix in groups if record["source"].startswith(prefix))
            groups[root].append(module)
    checked: dict[str, dict] = {}
    for prefix in groups:
        checked.update(lake_rehash_groups(sorted(groups[prefix]), lake))
    post_environment = environment_snapshot()
    if post_environment != environment:
        return {}
    result = {}
    for module, check in checked.items():
        before = pre.get(module)
        after = lake_candidate_snapshot(module, formal_records[module], graph,
                                        formal_records, external_roots, lean, lean_version,
                                        lake_path, environment)
        if before is None or after != before:
            continue
        result[module] = {"snapshot": before, "validation": check}
    return result


def receipt_object(module: str, source_record: dict[str, str],
                   expected_imports: dict[str, str], lean_sha256: str,
                   receipts: dict[str, list[dict]]) -> dict | None:
    """Return only a strict receipt object with exact source/import/toolchain pins."""
    expected_source = source_record.get("source")
    if not expected_source:
        return None
    for receipt in receipts.get(module, []):
        if (receipt.get("module") != module or receipt.get("exit_code") != 0
                or receipt.get("source_sha256_pre") != source_record["sha256"]
                or receipt.get("source_sha256_post") != source_record["sha256"]
                or receipt.get("lean_sha256") != lean_sha256):
            continue
        try:
            receipt_source = Path(receipt.get("source", "")).resolve().relative_to(REPO).as_posix()
        except (OSError, ValueError):
            continue
        if receipt_source != expected_source:
            continue
        hashes = receipt.get("dependency_hashes_pre_post", {})
        before, after = hashes.get("pre", {}), hashes.get("post", {})
        if not before or not after:
            continue
        common = set(before) & set(after)
        if any(before[path] != after[path] for path in common):
            continue
        if before.get(receipt.get("lean")) != lean_sha256:
            continue
        source_key = str(Path(receipt.get("source", "")).resolve())
        if before.get(source_key) != source_record["sha256"]:
            continue
        argv = receipt.get("argv", [])
        required_flags = {"-j1", "-DwarningAsError=true", "-DautoImplicit=false"}
        heartbeat_limits = [argument.split("=", 1)[1] for argument in argv
                            if argument.startswith("-DmaxHeartbeats=")]
        if (not required_flags.issubset(set(argv)) or len(heartbeat_limits) != 1
                or not heartbeat_limits[0].isdigit() or int(heartbeat_limits[0]) <= 0):
            continue
        if not retained_memory_budget_valid(argv):
            continue
        matched: dict[str, str] = {}
        for dependency, expected_hash in expected_imports.items():
            suffix = "/".join(dependency.split(".")) + ".olean"
            pre = [digest for path, digest in before.items()
                   if path.replace("\\", "/").endswith(suffix)]
            post = [digest for path, digest in after.items()
                    if path.replace("\\", "/").endswith(suffix)]
            if len(pre) != 1 or len(post) != 1 or pre[0] != expected_hash or post[0] != expected_hash:
                break
            matched[dependency] = pre[0]
        if matched != expected_imports:
            continue
        try:
            object_path = Path(argv[argv.index("-o") + 1])
        except (ValueError, IndexError):
            continue
        output_hash = receipt.get("output_sha256")
        if object_path.is_file() and output_hash and sha256_file(object_path) == output_hash:
            input_hashes_sha256 = sha256_bytes(json.dumps(
                {"pre": before, "post": after}, sort_keys=True,
                separators=(",", ":")).encode())
            receipt_sha256 = sha256_bytes(json.dumps(
                receipt, sort_keys=True, separators=(",", ":")).encode())
            return {
                "path": object_path,
                "provenance": {
                    "argv": list(argv),
                    "source": expected_source,
                    "source_sha256_pre": receipt["source_sha256_pre"],
                    "source_sha256_post": receipt["source_sha256_post"],
                    "lean": receipt["lean"],
                    "lean_sha256": receipt["lean_sha256"],
                    "imports": matched,
                    "output_sha256": output_hash,
                    "input_hashes_sha256": input_hashes_sha256,
                    "receipt_sha256": receipt_sha256,
                },
            }
    return None


def copy_verified_object(source: Path, target: Path, expected_hash: str,
                         label: str) -> str:
    """Install a pinned OLean into the package tree and verify before state credit."""
    source_hash = sha256_file(source)
    if source_hash != expected_hash:
        raise RuntimeError(f"{label} source hash mismatch: expected {expected_hash}, got {source_hash}")
    if not target.is_file() or sha256_file(target) != expected_hash:
        with tempfile.NamedTemporaryFile(prefix="rp05-copy-", suffix=".olean",
                                         dir=target.parent, delete=False) as tmp:
            temporary = Path(tmp.name)
        try:
            shutil.copyfile(source, temporary)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
    installed_hash = sha256_file(target)
    if installed_hash != expected_hash:
        raise RuntimeError(f"{label} copy hash mismatch: expected {expected_hash}, got {installed_hash}")
    return installed_hash


def read_only_check(manifest: dict) -> None:
    graph, source_hashes = checked_graph(manifest)
    roots = [entry["module"] for entry in manifest["public_roots"]]
    order = topological(graph, roots)
    lean, lake_path, version = lake_environment()
    lean_hash = sha256_file(Path(lean))
    output = BUILD_ROOT / "lib/lean"
    external_search = resolved_lake_paths(lake_path)
    state_path = BUILD_ROOT / "state.json"
    try:
        state = json.loads(state_path.read_text()).get("modules", {})
    except (OSError, json.JSONDecodeError):
        state = {}
    expected_modules = set(graph)
    if set(state) != expected_modules:
        raise RuntimeError("package build state does not exactly cover the source closure")
    expected_oleans = {module_path(module).with_suffix(".olean") for module in expected_modules}
    actual_oleans = ({path.relative_to(output) for path in output.rglob("*.olean")}
                     if output.exists() else set())
    if actual_oleans != expected_oleans:
        raise RuntimeError("package OLean tree contains missing or unmanifested modules")
    for module in order:
        source = graph[module]
        target = locate_object(module, [output])
        if target is None:
            raise RuntimeError(f"no package OLean for {module}; run `build` first")
        dep_hashes: dict[str, str] = {}
        for dependency in imports(source):
            search = [output] if dependency in graph else external_search
            obj = locate_object(dependency, search)
            if obj is None:
                raise RuntimeError(f"no OLean for imported module {dependency}")
            dep_hashes[dependency] = sha256_file(obj)
        entry = state.get(module, {})
        if not cache_state_matches(entry, source_hashes[module], dep_hashes,
                                   version, lean_hash, sha256_file(target)):
            raise RuntimeError(f"package object/state mismatch for {module}; run `build` then `check`")
    print(f"PASS read-only RP05 package check: {len(order)} modules, Lean {version}")


@contextmanager
def package_build_lock():
    """Hold a nonblocking, process-owned lock for the entire package build."""
    BUILD_ROOT.mkdir(parents=True, exist_ok=True)
    lock_path = BUILD_ROOT / ".build.lock"
    with lock_path.open("a+", encoding="ascii") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another RP05 package build is already active") from exc
        try:
            lock_file.seek(0)
            lock_file.truncate()
            lock_file.write(f"pid={os.getpid()}\n")
            lock_file.flush()
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def build(*, source_only: bool = False) -> None:
    # The process running this function holds the lock; an outer harness may
    # disappear while its child keeps running, so the child must own it itself.
    with package_build_lock():
        _build_locked(source_only=source_only)


def _build_locked(*, source_only: bool = False) -> None:
    manifest = verify_sources()
    graph, source_hashes = checked_graph(manifest)
    roots = [entry["module"] for entry in manifest["public_roots"]]
    order = topological(graph, roots)
    lean, lake_path, version = lake_environment()
    lean_hash = sha256_file(Path(lean))
    output = BUILD_ROOT / "lib/lean"
    output.mkdir(parents=True, exist_ok=True)
    external_search = resolved_lake_paths(lake_path)
    env = os.environ.copy()
    env["LEAN_PATH"] = os.pathsep.join([str(output), str(SOURCE_ROOT),
                                        *(str(path) for path in external_search)])
    state_path = BUILD_ROOT / "state.json"
    try:
        state = json.loads(state_path.read_text())
    except (OSError, json.JSONDecodeError):
        state = {}
    state_entries = state.get("modules", {})
    receipts = retained_receipts()
    lake_originals = validate_lake_originals(manifest, graph, external_search,
                                             lean, version, lake_path)
    print(f"Lake no-build validation: {len(lake_originals)} original objects validated; "
          f"{LAKE_FORMAL_COUNT - len(lake_originals)} unavailable or stale")
    built = reused = 0
    for module in order:
        source = graph[module]
        target = output / module_path(module).with_suffix(".olean")
        target.parent.mkdir(parents=True, exist_ok=True)
        dep_hashes: dict[str, str] = {}
        for dependency in imports(source):
            search = [output] if dependency in graph else external_search
            obj = locate_object(dependency, search)
            if obj is None:
                raise RuntimeError(f"no OLean for imported module {dependency} needed by {module}")
            dep_hashes[dependency] = sha256_file(obj)
        target_hash = sha256_file(target) if target.is_file() else None
        entry = state_entries.get(module, {})
        lake_candidate = lake_originals.get(module)
        if lake_candidate is not None:
            snapshot = lake_candidate["snapshot"]
            if dep_hashes == snapshot["imports"]:
                original_object = Path(snapshot["lake_object"])
                copied_hash = copy_verified_object(original_object, target,
                                                   snapshot["olean_sha256"],
                                                   f"Lake original {module}")
                state_entries[module] = {
                    "source_sha256": source_hashes[module],
                    "imports": dep_hashes,
                    "lean_version": version,
                    "lean_sha256": lean_hash,
                    "olean_sha256": copied_hash,
                    "lake_original_reuse": {
                        "source_sha256": snapshot["source_sha256"],
                        "staged_sha256": snapshot["staged_sha256"],
                        "imports": snapshot["imports"],
                        "trace": snapshot["trace"],
                        "lake_object": snapshot["lake_object"],
                        "validated_group": lake_candidate["validation"],
                    },
                }
                tmp_state = state_path.with_suffix(".json.tmp")
                tmp_state.write_text(json.dumps({"schema": "hegemon.rp05.build-state.v1",
                                                 "modules": state_entries}, indent=2,
                                                sort_keys=True) + "\n")
                os.replace(tmp_state, state_path)
                reused += 1
                continue
        cache_valid = (target_hash is not None
                       and cache_state_matches(entry, source_hashes[module], dep_hashes,
                                               version, lean_hash, target_hash))
        if source_only:
            if cache_valid:
                reused += 1
                continue
            raise RuntimeError(f"{module} is not reusable: source/import/compiler pins changed")
        source_record = next(record for record in manifest["sources"]
                             if record["module"] == module)
        retained = receipt_object(module, source_record, dep_hashes, lean_hash, receipts)
        if retained is not None:
            copied_hash = copy_verified_object(
                retained["path"], target, retained["provenance"]["output_sha256"],
                f"retained receipt {module}")
            state_entries[module] = {
                "source_sha256": source_hashes[module],
                "imports": dep_hashes,
                "lean_version": version,
                "lean_sha256": lean_hash,
                "olean_sha256": copied_hash,
                "retained_receipt_reuse": retained["provenance"],
            }
            tmp_state = state_path.with_suffix(".json.tmp")
            tmp_state.write_text(json.dumps({"schema": "hegemon.rp05.build-state.v1",
                                             "modules": state_entries}, indent=2, sort_keys=True) + "\n")
            os.replace(tmp_state, state_path)
            reused += 1
            continue
        if cache_valid:
            reused += 1
            continue
        with tempfile.NamedTemporaryFile(prefix="rp05-", suffix=".olean", dir=target.parent,
                                         delete=False) as tmp:
            temporary = Path(tmp.name)
        temporary.unlink(missing_ok=True)
        try:
            command = [lean, *STRICT_LEAN_FLAGS, "-o", str(temporary),
                       f"--root={SOURCE_ROOT}", str(source)]
            result = subprocess.run(command, cwd=REPO / "formal/crypto", env=env,
                                    text=True, capture_output=True, check=False,
                                    timeout=1800)
            if result.returncode:
                sys.stderr.write(result.stdout)
                sys.stderr.write(result.stderr)
                raise RuntimeError(f"Lean failed while compiling {module}")
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        state_entries[module] = {
            "source_sha256": source_hashes[module],
            "imports": dep_hashes,
            "lean_version": version,
            "lean_sha256": lean_hash,
            "olean_sha256": sha256_file(target),
        }
        state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_state = state_path.with_suffix(".json.tmp")
        tmp_state.write_text(json.dumps({"schema": "hegemon.rp05.build-state.v1",
                                         "modules": state_entries}, indent=2, sort_keys=True) + "\n")
        os.replace(tmp_state, state_path)
        built += 1
    if source_only:
        print(f"PASS build-cache check: {reused} modules match source, imports, compiler and package pins")
    else:
        print(f"PASS Lean package build: compiled {built}, reused {reused}, roots {len(roots)}")


def toy_test() -> None:
    """Small deterministic DAG exercise used by the unit test."""
    with tempfile.TemporaryDirectory(prefix="rp05-dag-") as tmp:
        root = Path(tmp)
        (root / "A.lean").write_text("import B\nimport External.Core\n")
        (root / "B.lean").write_text("import C\n")
        (root / "C.lean").write_text("-- leaf\n")
        (root / "Unused.lean").write_text("-- unreachable\n")
        index = {p.stem: p for p in root.glob("*.lean")}
        chosen, external = reachable(["A"], index, {"External"})
        assert set(chosen) == {"A", "B", "C"}
        assert external == ["External.Core"]
        assert topological(chosen, ["A"]) == ["C", "B", "A"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("stage", "inspect", "check-source", "build", "check", "test"))
    args = parser.parse_args()
    try:
        if args.command == "stage":
            stage()
        elif args.command == "inspect":
            manifest = load_manifest()
            print(json.dumps({"roots": manifest["public_roots"], "counts": manifest["counts"],
                              "external_imports": manifest["external_imports"]}, indent=2))
        elif args.command == "check-source":
            verify_sources()
        elif args.command == "build":
            build()
        elif args.command == "check":
            manifest = verify_sources()
            read_only_check(manifest)
        elif args.command == "test":
            toy_test()
            print("PASS toy DAG: reachability excludes unrelated sources; topological order is stable")
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
