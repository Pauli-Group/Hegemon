#!/usr/bin/env python3
"""RP05 CI: base/supplemental source guards, incremental compilation, body audit.

Never consumes package build/state.json, retained receipts, or original project
objects. Cache directory must come only from trusted default-branch CI. Hashes
establish cache provenance, not kernel validity. Cold mode replays every project
module with the pinned toolchain's leanchecker (same kernel, not external verifier).
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rp05_proof_package as package

FLAGS = ['-j1', '-M4000', '-DwarningAsError=true', '-DautoImplicit=false', '-DElab.async=false']
# Unlike collectAxioms, this deliberately never reads the imported axiom-summary extension.
BODY_AUDIT = r'''import Lean.Environment
import Lean.CoreM
import Lean.Data.Json
open Lean
partial def walk (env : Environment) (seen : IO.Ref NameSet) (name : Name) : IO Unit := do
  if (← seen.get).contains name then return
  seen.modify (·.insert name)
  let some ci := env.checked.get.find? name
    | throw <| IO.userError s!"missing constant/body: {name}"
  if ci.isUnsafe || ci.isPartial then
    throw <| IO.userError s!"unsafe/partial dependency: {name}"
  let visit (e : Expr) : IO Unit := do
    if e.hasLooseBVars || e.hasFVar || e.hasMVar then
      throw <| IO.userError s!"missing/incomplete body: {name}"
    e.getUsedConstants.forM (walk env seen)
  visit ci.type
  match ci with
  | .axiomInfo _ =>
    unless name == ``propext || name == ``Classical.choice || name == ``Quot.sound do
      throw <| IO.userError s!"forbidden axiom (including native_decide/sorry): {name}"
  | .defnInfo v => visit v.value
  | .thmInfo v => visit v.value
  | .opaqueInfo v => visit v.value
  | .inductInfo v => v.ctors.forM (walk env seen)
  | .recInfo v => v.rules.forM (fun r => visit r.rhs)
  | .ctorInfo _ => pure ()
  | .quotInfo _ => pure ()
unsafe def main (args : List String) : IO UInt32 := do
  let [moduleName, rootName] := args
    | throw <| IO.userError "expected module and root"
  initSearchPath (← findSysroot)
  let env ← importModules (loadExts := false) (level := OLeanLevel.private)
    #[{ module := moduleName.toName }] {} 0 #[]
  let some ci := env.checked.get.find? rootName.toName
    | throw <| IO.userError "missing public root"
  unless ci.hasValue (allowOpaque := true) do
    throw <| IO.userError "public root has no body"
  let seen ← IO.mkRef ({} : NameSet)
  walk env seen rootName.toName
  IO.println (Json.mkObj [("root", toJson rootName),
    ("visited", toJson (← seen.get).toArray.size),
    ("policy", toJson "actual-bodies-standard-axioms-only")]).compress
  return 0
'''


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def safe_file(root, relative):
    p = root / relative
    if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root.resolve()):
        raise RuntimeError(f'unsafe/missing input: {relative}')
    return p


def supplemental_graph(graph, registry=None):
    """Extend the staged graph with reviewed flat shared/*.lean entries only."""
    registry = registry or package.PACKAGE/'supplemental-roots.json'
    if not registry.exists():
        return dict(graph), []
    safe_file(package.PACKAGE, registry.relative_to(package.PACKAGE))
    data = json.loads(registry.read_text())
    if (not isinstance(data, dict) or set(data) != {'schema','entries'}
            or data['schema'] != 'hegemon.rp05.supplemental-roots.v1'
            or not isinstance(data['entries'], list)):
        raise RuntimeError('invalid supplemental registry schema')
    combined = dict(graph)
    entries = []
    for entry in data['entries']:
        if not isinstance(entry, dict) or set(entry) != {'module','path','sha256','theorems'}:
            raise RuntimeError('invalid supplemental entry')
        module = entry['module']
        if not isinstance(module,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*',module):
            raise RuntimeError('supplemental module must be a flat Lean module name')
        if module in combined or module in package.EXTERNAL_ROOTS:
            raise RuntimeError('supplemental module shadows an existing module: '+module)
        if entry['path'] != 'shared/'+module+'.lean':
            raise RuntimeError('supplemental path must be shared/<module>.lean')
        source = safe_file(package.PACKAGE, entry['path'])
        if package.sha256_file(source) != entry['sha256']:
            raise RuntimeError('supplemental source hash mismatch: '+module)
        names = entry['theorems']
        if (not isinstance(names,list) or not names
                or any(not isinstance(n,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*',n)
                       for n in names) or len(set(names)) != len(names)):
            raise RuntimeError('invalid supplemental theorem roots')
        combined[module] = source
        entries.append(entry)
    # Resolving all registry modules catches forward imports, cycles and undeclared
    # project helpers. Only the established external namespace allowlist is allowed.
    package.reachable([e['module'] for e in entries], combined, package.EXTERNAL_ROOTS)
    return combined, entries


def audit_roots(manifest):
    roots = [(e['module'],e['theorem']) for e in manifest['public_roots']]
    return roots + [(e['module'],t) for e in manifest['supplemental_roots'] for t in e['theorems']]


def proof_inputs(manifest, graph):
    """Documentation/tests alone do not invalidate compiled theorem inputs."""
    return ({r['source'] for r in manifest['sources']}
            | {p.relative_to(package.REPO).as_posix() for p in graph.values()}
            | {manifest['toolchain'][k] for k in
               ('lean_toolchain_path', 'lakefile_path', 'lake_manifest_path')}
            | {'formal/rp05/source-manifest.json', 'formal/rp05/supplemental-roots.json',
               'scripts/rp05_ci.py', 'scripts/rp05_proof_package.py',
               '.github/workflows/rp05-proof.yml'})


def graph_key(inputs, manifest, graph, order):
    return digest([inputs, [(n,package.sha256_file(graph[n]),package.imports(graph[n])) for n in order],
                   audit_roots(manifest)])


def source_guard():
    """No Lean/Lake execution, no retained .agent tree scan."""
    m = package.load_manifest()
    for r in m['sources']:
        if r['staged'] != 'generated/Sources/' + package.module_path(r['module']).as_posix():
            raise RuntimeError('noncanonical staged path')
        safe_file(package.PACKAGE, r['staged'])
    graph, hashes = package.checked_graph(m)
    package.validate_source_pins(m)
    roots = [x['module'] for x in m['public_roots']]
    if set(roots) != package.EXPECTED_PUBLIC or len(roots) != 4:
        raise RuntimeError('public roots changed')
    selected, external = package.reachable(roots, graph, package.EXTERNAL_ROOTS)
    if set(selected) != set(graph) or external != m['external_imports']:
        raise RuntimeError('source/import closure changed')
    for entry in m['public_roots']:
        name, endpoint = package.PUBLIC_ENDPOINTS[entry['module']]
        if entry['theorem'] != name or entry['endpoint_module'] != endpoint:
            raise RuntimeError('public claim contract changed')
        if package.imports(graph[entry['module']]) != [endpoint]:
            raise RuntimeError('public wrapper import changed')
        wrapper = safe_file(package.PACKAGE, package.module_path(entry['module']))
        if package.sha256_file(wrapper) != hashes[entry['module']]:
            raise RuntimeError('public wrapper/staged source drift')
    for path_key, hash_key in [('lean_toolchain_path','lean_toolchain_sha256'),
                              ('lakefile_path','lakefile_sha256'),
                              ('lake_manifest_path','lake_manifest_sha256')]:
        p = safe_file(package.REPO, m['toolchain'][path_key])
        if package.sha256_file(p) != m['toolchain'][hash_key]:
            raise RuntimeError('toolchain/lock pin drift')
    # Check only manifest-selected maintained originals; retained scratch is not required.
    for r in m['sources']:
        if r['source'].startswith(('formal/crypto/', 'formal/lean/', 'formal/rp05/')):
            if package.sha256_file(safe_file(package.REPO, r['source'])) != r['sha256']:
                raise RuntimeError('maintained original/staged drift: ' + r['module'])
    graph, supplements = supplemental_graph(graph)
    m = dict(m, supplemental_roots=supplements)
    return m, graph, package.topological(graph, roots+[e["module"] for e in supplements])


def run(command, env, deadline, limit=120):
    remaining = min(limit, deadline-time.monotonic())
    if remaining <= 0:
        raise RuntimeError('CI time budget exhausted; run cold/manual lane to seed trusted cache')
    proc = subprocess.Popen(command, cwd=package.REPO/'formal/crypto', env=env, start_new_session=True)
    try:
        if proc.wait(timeout=remaining):
            raise RuntimeError('command failed: ' + repr(command))
    except BaseException:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        raise


def library_inputs(lean, external):
    """Pin all library parts, not merely directly imported olean files."""
    toolchain = Path(lean).resolve().parents[1]
    roots = [toolchain/'bin', toolchain/'lib', *external]
    records = []
    for i, root in enumerate(roots):
        for p in sorted(root.rglob('*')):
            if p.is_file():
                records.append([i, p.relative_to(root).as_posix(), package.sha256_file(p)])
    return digest(records)


def environment(cache):
    lean, lake_path, version = package.lake_environment()
    core = Path(lean).resolve().parents[1]/'lib/lean'
    external = [p for p in package.resolved_lake_paths(lake_path)
                if '.lake/packages/' in p.as_posix()]
    # No formal/crypto or formal/lean project build directory is admitted.
    external.append(core)
    fingerprint = digest({'libraries': library_inputs(lean, external), 'version': version,
                          'flags': FLAGS, 'policy': package.sha256_file(Path(__file__))})
    env = dict(os.environ, PATH=str(Path(lean).resolve().parent)+os.pathsep+os.environ.get('PATH',''),
               LEAN_PATH=os.pathsep.join(map(str, [cache/'objects', *external])))
    return lean, env, external, fingerprint


def module_key(source_hash, dependencies, inputs):
    # Ordered dependency list: changing import order invalidates reuse.
    return digest([source_hash, dependencies, inputs])


def object_parts(target):
    if any(p.is_symlink() for p in target.parent.glob(target.name+'*')):
        raise RuntimeError('symlink compiler object')
    return {p.name: package.sha256_file(p) for p in sorted(target.parent.glob(target.name+'*'))
            if p.is_file() and not p.is_symlink()}


def prepare(cache, cold):
    m, graph, order = source_guard()
    lean, env, external, inputs = environment(cache)
    key = graph_key(inputs, m, graph, order)
    data = {'inputs': inputs, 'key': key, 'prefix': 'rp05-v1-'+inputs+'-', 'lean': lean,
            'external': list(map(str, external)), 'cold': cold}
    cache.parent.mkdir(parents=True, exist_ok=True)
    (cache.parent/'inputs.json').write_text(json.dumps(data))
    out = os.getenv('GITHUB_OUTPUT')
    if out:
        with open(out,'a') as f:
            f.write('key='+data['prefix']+key+'\nprefix='+data['prefix']+'\n')
    print(json.dumps({'policy':'no-record audit until compiler inputs available', **data}))


def compile_audit(cache, cold, seconds):
    deadline = time.monotonic()+seconds
    m, graph, order = source_guard()
    lean, env, external, inputs = environment(cache)
    prepared = json.loads((cache.parent/'inputs.json').read_text())
    if inputs != prepared['inputs']:
        raise RuntimeError('compiler/library input drift')
    if cold and cache.exists():
        raise RuntimeError('cold lane requires an empty project cache directory')
    cache.mkdir(parents=True, exist_ok=True)
    state_path = cache/'state.json'
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    state = {n:e for n,e in state.items() if n in graph}
    expected_objects = {str(package.module_path(n).with_suffix('.olean')) for n in graph}
    for old in (cache/'objects').rglob('*.olean*'):
        relative = str(old.relative_to(cache/'objects')).split('.olean')[0]+'.olean'
        if relative not in expected_objects:
            old.unlink()
    source_before = {n:package.sha256_file(p) for n,p in graph.items()}
    built = reused = 0
    for module in order:
        source = graph[module]
        target = cache/'objects'/package.module_path(module).with_suffix('.olean')
        deps = []
        for name in package.imports(source):
            obj = package.locate_object(name, [cache/'objects'] if name in graph else external)
            if obj is None:
                raise RuntimeError('missing compiler input: '+name)
            deps.append([name, object_parts(obj)])
        key = module_key(package.sha256_file(source), deps, inputs)
        entry = state.get(module, {})
        parts = object_parts(target)
        if not cold and target.is_file() and entry == {'key':key, 'parts':parts}:
            reused += 1
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        # Remove only invalidated outputs inside the dedicated disposable CI cache.
        for p in target.parent.glob(target.name+'*'):
            p.unlink()
        source_root = package.SOURCE_ROOT if source.is_relative_to(package.SOURCE_ROOT) else package.PACKAGE/'shared'
        # Measured finite checking took 254.11s total (241s in kernel scopes,
        # max 4.13s per scope); retain bounded phases and the aggregate deadline.
        run([lean,*FLAGS,'-o',str(target),f'--root={source_root}',str(source)],env,deadline,360)
        if not target.is_file():
            raise RuntimeError('compiler did not produce object')
        state[module] = {'key':key, 'parts':object_parts(target)}
        state_path.write_text(json.dumps(state,sort_keys=True))
        built += 1
    audit = cache/'BodyAudit.lean'
    audit.write_text(BODY_AUDIT)
    for module, theorem in audit_roots(m):
        run([lean,'-j1','-M4000','--run',str(audit),module,theorem],env,deadline,180)
    if cold:
        checker = str(Path(lean).with_name('leanchecker'))
        if not Path(checker).is_file():
            raise RuntimeError('pinned toolchain leanchecker unavailable; kernel replay not verified')
        for module in order:
            run([checker,module],env,deadline,360)
    # Fail closed on source or compiler/library mutation during compilation/auditing.
    manifest_after, graph_after, order_after = source_guard()
    if graph_key(inputs,m,graph,order) != graph_key(inputs,manifest_after,graph_after,order_after):
        raise RuntimeError('source graph/audit roots changed during verification')
    if source_before != {n:package.sha256_file(p) for n,p in graph.items()}:
        raise RuntimeError('source inputs changed during verification')
    if environment(cache)[3] != inputs:
        raise RuntimeError('compiler/library inputs changed during verification')
    if time.monotonic() > deadline:
        raise RuntimeError('total CI verification deadline exceeded')
    result = {'status':'PASS','mode':'cold-project-compile-and-kernel-replay' if cold else 'incremental-project-compile',
              'compiled':built,'reused':reused,'base_public_roots':4,'actual_public_root_body_audits':4,
              'supplemental_modules':len(m['supplemental_roots']),
              'supplemental_theorem_body_audits':len(audit_roots(m))-4,
              'kernel_replayed_project_modules':len(order) if cold else 0,
              'external_libraries':'pinned cached inputs; not independently replayed',
              'production_authority':False,'seconds':round(seconds-(deadline-time.monotonic()),2)}
    (cache.parent/'result.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result))
    if os.getenv('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f:
            f.write('RP05 CI: `'+json.dumps(result)+'`\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['source','prepare','verify'])
    p.add_argument('--cache',type=Path,default=Path(os.getenv('RUNNER_TEMP','/tmp'))/'rp05-ci/cache')
    p.add_argument('--cold',action='store_true')
    p.add_argument('--seconds',type=int,default=600)
    a=p.parse_args()
    if a.command=='source':
        m,g,_=source_guard()
        proof = True
        base = os.getenv('RP05_BASE_SHA')
        if base:
            names = subprocess.check_output(['git','diff','--name-only',base,'HEAD'],cwd=package.REPO,text=True).splitlines()
            proof = any(n in proof_inputs(m, g) for n in names)
        if os.getenv('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'],'a') as f: f.write('proof='+str(proof).lower()+'\n')
        print(json.dumps({'status':'PASS','mode':'source-only-no-kernel-claim','modules':len(g),'base_public_roots':4,'supplemental_modules':len(m['supplemental_roots']),
                          'supplemental_theorem_roots':len(audit_roots(m))-4,'proof_changed':proof}))
    elif a.command=='prepare': prepare(a.cache,a.cold)
    else: compile_audit(a.cache,a.cold,a.seconds)
if __name__=='__main__':
    try: main()
    except (RuntimeError,OSError,ValueError) as e:
        print('FAIL RP05 CI: '+str(e),file=sys.stderr);sys.exit(1)
