#!/usr/bin/env python3
"""Stage4 R3: protected ownership, metadata-independent signals, cleanup watchdog."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import threading

ROOT=Path('/private/tmp/smz9-aeneas-stage1.IgNKumAA')
OLD=Path('/private/tmp/smz9-native-tools.lS4uVwgg')
SPEC_FILE=ROOT/'STAGE4_INSTRUMENTATION_SPEC.json'
SPEC_HASH='9d394e2ac63abd4586fdeb683d0d5c2b4316a7c702c75d4c471411eff886e9c6'
SPEC=json.loads(SPEC_FILE.read_text())
STAGE=Path(SPEC['new_stage_directory'])
COPY=Path(SPEC['source_copy']['destination'])
PROFILE=Path(SPEC['sandbox_profile_path'])
KEEP=['HOME','CODEX_HOME','USER','LOGNAME','SHELL','LANG','LC_ALL','__CF_USER_TEXT_ENCODING']
ENV={k:os.environ[k] for k in KEEP if k in os.environ}
ENV.update(SPEC['environment'])
MODE=None
REPORT={}
REPORT_FILE=None
DEADLINE=None
LAST_SUCCESS=None
START=None
R1_RUNNER_SHA='b89824455a000dc243c11c2b33707b45b44d59f4a2517ce6b72bb6b770b51b13'

def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def persist():
    if REPORT_FILE is not None:
        REPORT_FILE.write_text(json.dumps(REPORT,indent=2)+'\n')

def resources():
    global LAST_SUCCESS
    limits=SPEC['proposed_limits']
    check_started=time.monotonic()
    for attempt in range(3):
        df=subprocess.check_output(['/bin/df','-k',str(ROOT)],text=True,timeout=5)
        free=int(df.splitlines()[-1].split()[3])*1024
        if free <= limits['stop_available_bytes'] or time.time() >= DEADLINE-15:
            raise RuntimeError('Conservative free-space/time threshold reached')
        result=subprocess.run(['/usr/bin/du','-sk',str(ROOT)],text=True,capture_output=True,timeout=8)
        if result.returncode==0:
            used=int(result.stdout.split()[0])*1024
            now=time.monotonic()
            gap=None if LAST_SUCCESS is None else now-LAST_SUCCESS
            sample={'time':time.time(),'monotonic_seconds':now,'allocated_bytes':used,
                    'apfs_available_bytes':free,'successful_sample_gap_seconds':gap}
            REPORT['resource_samples'].append(sample)
            if gap is not None:
                REPORT['maximum_successful_sample_gap_seconds']=max(
                    REPORT.get('maximum_successful_sample_gap_seconds',0),gap)
            LAST_SUCCESS=now
            persist()
            if gap is not None and gap>15:
                raise RuntimeError('Actual complete successful resource sample gap exceeded15seconds')
            if used >= limits['stop_allocated_bytes']:
                raise RuntimeError('Conservative allocated-root threshold reached')
            return sample
        lines=result.stderr.strip().splitlines()
        allowed=bool(lines)
        for line in lines:
            match=re.fullmatch(r'(?:du|/usr/bin/du): (.+): No such file or directory',line)
            if not match or not any(match.group(1).startswith(str(STAGE/x)+'/') for x in ['build','tmp']):
                allowed=False
        REPORT['transient_du_errors'].append({'time':time.time(),'attempt':attempt,
            'exit_code':result.returncode,'stderr':result.stderr,'discarded_partial_stdout':result.stdout})
        persist()
        if not allowed or attempt==2 or time.monotonic()-check_started>8:
            raise RuntimeError('du failed; no complete successful resource measurement')
        time.sleep(1)
    raise AssertionError('unreachable')

def tick():
    if LAST_SUCCESS is not None and time.monotonic()-LAST_SUCCESS>=4:
        resources()

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):
            h.update(chunk)
            tick()
    return h.hexdigest()

ACTIVE_GROUPS={}

class ChildProcessGroup:
    """Reserve the Popen child until group extinction is independently verified."""
    def __init__(self,audit):
        # Construct before Popen: failures here cannot strand a new child.
        assert signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL
        self.parent_pgid=os.getpgrp()
        self.proc=None
        self.pgid=None
        self.reserved=False
        self.retired=False
        self.cleanup_attempted=False
        self.audit=audit
        self.lock=threading.Lock()
        self.timer=None
        self.kill_event=threading.Event()

    def attach(self,proc):
        # First post-Popen action: only ownership assignments, no metadata or I/O.
        self.proc=proc
        self.pgid=proc.pid
        self.reserved=True
        ACTIVE_GROUPS[self.pgid]=self
        self.audit.update(pid=self.pgid,pgid=self.pgid,group_signals=[],group_samples=[])
        assert self.pgid>1 and self.pgid!=self.parent_pgid

    def leader_exited(self):
        assert self.reserved and not self.retired and self.proc.returncode is None
        info=os.waitid(os.P_PID,self.proc.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        if info is not None:
            assert info.si_pid==self.proc.pid
        return info is not None

    def members(self,timeout=0.2):
        assert self.reserved and not self.retired
        # Target only this process-group leader, never a full process-table scan.
        result=subprocess.run(['/bin/ps','-p',str(self.proc.pid),'-g',str(self.pgid),
            '-o','pid=,pgid=,stat='],
            env=ENV,text=True,capture_output=True,check=True,timeout=timeout)
        rows=[]
        for line in result.stdout.splitlines():
            parts=line.split()
            assert len(parts)==3 and parts[0].isdigit() and parts[1].isdigit()
            assert int(parts[1])==self.pgid
            rows.append({'pid':int(parts[0]),'pgid':int(parts[1]),'stat':parts[2]})
        assert any(x['pid']==self.proc.pid for x in rows),'Reserved leader missing from metadata'
        self.audit['group_samples'].append({'time':time.time(),'members':rows})
        return rows

    def initialize_metadata(self):
        # Kept inside run's protected region; it is not required for signaling.
        self.members()

    def send(self,sig):
        # No ps, getpgid, waitid, resource scan, receipt write or other callback.
        # Popen(start_new_session=True) established this PGID, and no code reaps
        # its direct child before the reserved flag is cleared under this lock.
        with self.lock:
            if not self.reserved or self.retired:
                raise RuntimeError('Refusing signal after PID reservation release')
            attempt={'time':time.time(),'monotonic_seconds':time.monotonic(),'signal':int(sig)}
            try:
                os.killpg(self.pgid,sig)
                attempt['delivered']=True
            except (ProcessLookupError,PermissionError) as exc:
                # macOS may reject signaling a group containing only zombies.
                # This does not prove extinction and must not bypass metadata.
                attempt.update(delivered=False,error=repr(exc))
            self.audit['group_signals'].append(attempt)
            if sig==signal.SIGKILL:
                self.kill_event.set()

    def _kill_watchdog(self):
        try:
            self.send(signal.SIGKILL)
        except BaseException as exc:
            self.audit.setdefault('watchdog_errors',[]).append(repr(exc))
            self.kill_event.set()

    def cancel_watchdog(self):
        timer=self.timer
        if timer is not None:
            timer.cancel()
            timer.join(timeout=1)
            if timer.is_alive():
                raise RuntimeError('Watchdog still active: keep original PID reserved')
            self.timer=None

    def can_reap(self,timeout=0.2):
        rows=self.members(timeout)
        return self.leader_exited() and all(x['pid']==self.proc.pid for x in rows)

    def confirm_and_retire(self):
        # Fresh complete metadata, not just a signal return, is mandatory.
        assert self.can_reap()
        self.cancel_watchdog()
        with self.lock:
            assert self.reserved and not self.retired and self.leader_exited()
            self.reserved=False
            self.retired=True
            self.proc.wait(timeout=1)
        ACTIVE_GROUPS.pop(self.pgid,None)
        try:
            os.killpg(self.pgid,0)
        except ProcessLookupError:
            self.audit.update(group_extinct=True,leader_reaped_after_group_cleanup=True)
            return
        raise RuntimeError('PGID exists after reap; never signal a possibly reused group')

    def finish(self,terminate=False):
        if self.retired:
            assert self.audit.get('group_extinct') is True
            return
        if self.cleanup_attempted:
            raise RuntimeError('Group cleanup already attempted; refusing a second signal cycle')
        if not terminate and self.can_reap():
            self.confirm_and_retire()
            return
        self.cleanup_attempted=True
        self.audit['surviving_group_on_nominal_completion']=not terminate
        self.send(signal.SIGTERM)
        term_time=self.audit['group_signals'][-1]['monotonic_seconds']
        self.audit['term_deadline_monotonic']=term_time+10
        cleanup_deadline=term_time+15
        self.timer=threading.Timer(max(0,term_time+10-time.monotonic()),self._kill_watchdog)
        self.timer.daemon=True
        try:
            self.timer.start()
        except BaseException as exc:
            self.audit['watchdog_start_failure']=repr(exc)
            self.timer=None
            self.send(signal.SIGKILL)
            cleanup_deadline=time.monotonic()+5
        try:
            while time.monotonic()<cleanup_deadline:
                remaining=cleanup_deadline-time.monotonic()
                if remaining<=0:
                    break
                metadata_ok=False
                try:
                    metadata_ok=self.can_reap(timeout=min(0.2,remaining))
                except BaseException as exc:
                    self.audit.setdefault('cleanup_metadata_errors',[]).append(repr(exc))
                    if self.kill_event.is_set():
                        break
                if metadata_ok:
                    self.confirm_and_retire()
                    if not terminate:
                        raise RuntimeError('Leader exited with surviving descendants; cleaned group, rejecting nominal completion')
                    return
                # No tick/resources/persist callback runs in cleanup. The separate
                # watchdog signals on its deadline even if ps is slow or failing.
                time.sleep(min(0.02,max(0,cleanup_deadline-time.monotonic())))
            self.audit['cleanup_unconfirmed_reserved_pid']=self.pgid
            raise RuntimeError('Group extinction unconfirmed: keep owned leader unreaped, reject command')
        finally:
            self.cancel_watchdog()

def stop_group(group):
    group.finish(terminate=True)

def run(name,argv,cwd=None,expected_exit=0,long=False):
    resources()
    log=STAGE/'logs'/(MODE+'-'+name+'.log')
    assert not log.exists(),name
    item={'name':name,'argv':argv,'cwd':str(cwd or STAGE),'started':time.time(),
          'log':str(log),'expected_exit':expected_exit}
    REPORT['commands'].append(item)
    persist()
    print('START '+name,flush=True)
    with log.open('xb') as output:
        group=ChildProcessGroup(item)
        proc=None
        try:
            proc=subprocess.Popen(argv,cwd=str(cwd or STAGE),env=ENV,stdout=output,
                                  stderr=subprocess.STDOUT,start_new_session=True)
            group.attach(proc)
            group.initialize_metadata()
            persist()
            while not group.leader_exited():
                time.sleep(0.25)
                tick()
                if not long and time.time()-item['started']>120:
                    raise RuntimeError(name+' exceeded120-second diagnostic bound')
            group.finish()
        except BaseException as original:
            if proc is not None:
                if group.proc is None:
                    group.attach(proc)
                try:
                    stop_group(group)
                except BaseException as cleanup:
                    item['cleanup_failure']=repr(cleanup)
                    item.update(stopped=True,exit_code=proc.returncode,seconds=time.time()-item['started'])
                    persist()
                    raise RuntimeError('Command failed and process-group extinction could not be confirmed') from original
                item.update(stopped=True,exit_code=proc.returncode,seconds=time.time()-item['started'])
                persist()
            raise
    assert item.get('group_extinct') is True
    item.update(exit_code=proc.returncode,seconds=time.time()-item['started'],log_sha256=digest(log))
    persist()
    content=log.read_text(errors='replace')
    print('END '+name+' exit='+str(proc.returncode),flush=True)
    if proc.returncode!=expected_exit:
        print(content[-24000:],flush=True)
        raise RuntimeError(name+' unexpected exit; no retry, sandbox expansion or semantic patch')
    resources()
    return content

def relative_path(root,rel):
    p=Path(rel)
    assert not p.is_absolute() and '..' not in p.parts and '.' not in p.parts and p.parts,rel
    target=root/p
    current=root
    assert root.is_dir() and not root.is_symlink(),str(root)
    for part in p.parts[:-1]:
        current=current/part
        assert current.is_dir() and not current.is_symlink(),str(current)
    assert target.parent.resolve().is_relative_to(root.resolve()),str(target)
    return target

def manifests():
    result=[]
    for index,item in enumerate(SPEC['source_copy']['manifests']):
        path=Path(item['path'])
        assert digest(path)==item['sha256'],str(path)
        records=json.loads(path.read_text())
        assert len(records)==item['entries']
        assert len({x['path'] for x in records})==len(records)
        result.append((index,records))
    return result

def inventory(root,records,original=False,patched=False):
    expected={x['path'] for x in records}
    actual=set()
    for directory,dirs,files in os.walk(root,followlinks=False):
        tick()
        base=Path(directory)
        if base==root:
            dirs[:]=[d for d in dirs if not (original and d=='.git') and
                     not (root in [ROOT/'aeneas',COPY] and d=='charon')]
        for name in files:
            actual.add(str((base/name).relative_to(root)))
        for name in dirs:
            path=base/name
            if path.is_symlink():
                actual.add(str(path.relative_to(root)))
    assert actual==expected,('source inventory set',str(root),sorted(actual-expected),sorted(expected-actual))
    observed=[]
    for item in records:
        tick()
        path=relative_path(root,item['path'])
        mode=path.lstat().st_mode
        if 'symlink' in item:
            assert stat.S_ISLNK(mode) and os.readlink(path)==item['symlink'],str(path)
            # Broken documentation links are retained, not followed. All link targets
            # must remain lexically inside the enclosing copied/original Aeneas tree.
            boundary=ROOT/'aeneas' if original else COPY
            assert Path(os.path.normpath(path.parent/item['symlink'])).is_relative_to(boundary),str(path)
            observed.append(dict(item))
        else:
            assert stat.S_ISREG(mode) and stat.S_IMODE(mode)==item['mode'],str(path)
            want=item['sha256']
            if patched and path==Path(SPEC['instrumentation_patch']['copied_target']):
                want=SPEC['instrumentation_patch']['prospective_instrumented_source_sha256']
            assert digest(path)==want,str(path)
            if not original:
                src=relative_path(ROOT/'aeneas' if root==COPY else ROOT/'aeneas/charon',item['path'])
                assert (path.stat().st_dev,path.stat().st_ino)!=(src.stat().st_dev,src.stat().st_ino),str(path)
                assert path.stat().st_nlink==1,str(path)
            observed.append({**item,'sha256':want})
    return observed

def verify_sources(label,check_copy=False,patched=False):
    for index,pin in enumerate(SPEC['source_pins']):
        repo=Path(pin['path'])
        argv=['/opt/homebrew/bin/git','-C',str(repo)]
        ids=run(label+'-source-'+str(index)+'-identity',argv+['rev-parse','HEAD','HEAD^{tree}']).splitlines()
        assert ids==[pin['commit'],pin['tree']]
        assert not run(label+'-source-'+str(index)+'-tracked',argv+['diff','--name-status','HEAD','--']).strip()
    for index,records in manifests():
        src=ROOT/'aeneas' if index==0 else ROOT/'aeneas/charon'
        inventory(src,records,original=True)
        if check_copy:
            dest=COPY if index==0 else COPY/'charon'
            seen=inventory(dest,records,patched=patched)
            REPORT[label+'-copy-inventory-'+str(index)]={
                'entries':len(seen),'sha256':hashlib.sha256(json.dumps(seen,sort_keys=True).encode()).hexdigest()}
    pin_lines=[x.strip() for x in (ROOT/'aeneas/charon-pin').read_text().splitlines()
               if x.strip() and not x.lstrip().startswith('#')]
    assert pin_lines==[SPEC['source_pins'][1]['commit']]
    assert os.readlink(ROOT/'aeneas/src/charon')=='../charon'
    if check_copy:
        assert os.readlink(COPY/'src/charon')=='../charon'
        assert (COPY/'src/charon').resolve()==COPY/'charon'
    REPORT[label+'_source_pins']='all original pins/inventories exact; copied inventories checked when requested'
    persist()

def expected_patched_bytes():
    patch=SPEC['instrumentation_patch']
    p=Path(patch['path'])
    assert digest(p)==patch['sha256']
    original=Path(patch['original_target']).read_bytes()
    assert hashlib.sha256(original).hexdigest()==patch['original_sha256']
    lines=p.read_text().splitlines(keepends=True)
    assert lines[:3]==['--- a/src/interp/InterpProjectors.ml\n',
                       '+++ b/src/interp/InterpProjectors.ml\n','@@ -106,7 +106,23 @@\n']
    hunk=lines[3:]
    assert all(x.startswith((' ','+')) for x in hunk)
    old=''.join(x[1:] for x in hunk if x[0]==' ').encode()
    new=''.join(x[1:] for x in hunk).encode()
    assert original.count(old)==1
    assert len([x for x in hunk if x.startswith('+')])==16
    answer=original.replace(old,new,1)
    assert answer.splitlines()[124]==b'  [%sanity_check] span (ty_is_rty ty && ety = v.ty);'
    assert hashlib.sha256(answer).hexdigest()==patch['prospective_instrumented_source_sha256']
    return answer

def verify_installed_and_inputs(label):
    h=SPEC['protected_sha256']
    protected={
        ROOT/'stage2-postflight.json':h['stage2_postflight'],
        ROOT/'stage2-installed-artifacts.json':h['installed_manifest'],
        ROOT/'exact-packages.txt':h['exact_packages'],
        ROOT/'opam-root/config':h['opam_root_config'],
        ROOT/'opam-root/opam-init/hooks/sandbox.sh':h['opam_sandbox_hook'],
        ROOT/'ocaml-switch/_opam/bin/dune':h['dune'],
        ROOT/'ocaml-switch/_opam/bin/ocamlc':h['ocamlc'],
        ROOT/'ocaml-switch/_opam/bin/ocamlopt':h['ocamlopt'],
        OLD/'runtime/aeneas':h['release_aeneas']}
    for key in ['specification','runner','receipt','executable']:
        protected[Path(SPEC['protected_baseline'][key+'_path'])]=SPEC['protected_baseline'][key+'_sha256']
    for path,want in protected.items():
        assert digest(path)==want,('protected hash',str(path))
    manifest=json.loads((ROOT/'stage2-installed-artifacts.json').read_text())
    switch=Path(manifest['switch'])
    for item in manifest['records']:
        tick()
        path=switch/item['relative_path']
        mode=path.lstat().st_mode
        if item['kind']=='file':
            assert stat.S_ISREG(mode) and stat.S_IMODE(mode)==item['mode'],str(path)
            assert path.stat().st_size==item['bytes'] and digest(path)==item['sha256'],str(path)
        else:
            assert path.is_symlink() and os.readlink(path)==item['target'],str(path)
            assert str(path.resolve(strict=True))==item['resolved_path'],str(path)
    for item in manifest['native_dylibs']:
        path=Path(item['loader_path'])
        assert str(path.resolve(strict=True))==item['resolved_path']
        assert digest(path)==item['sha256'],str(path)
    for test in SPEC['tests']:
        if 'input' in test:
            assert digest(Path(test['input']))==test['input_sha256'],test['input']
        for item in test.get('files',[]):
            assert digest(Path(item['retained_path']))==item['sha256']
            assert digest(ROOT/'stage3-baseline/out'/test['name']/item['relative_path'])==item['sha256']
    assert digest(SPEC_FILE)==SPEC_HASH
    assert PROFILE.read_text()==SPEC['sandbox_profile_text']
    assert digest(PROFILE)=='48de8cda9f266d037108f8bbc2575c1609c9d2ee75533bbeb48330c30960f60f'
    expected_patched_bytes()
    REPORT[label+'_installed_and_inputs']={'installed_records':len(manifest['records']),
        'native_dylibs':len(manifest['native_dylibs']),'llbc_inputs':4,
        'old_scalar_outputs':6,'baseline_scalar_outputs':6,'all_hashes_equal':True}
    persist()
    print('PASS '+label+' full installed/native/baseline/input/policy checks',flush=True)

def create_directories():
    assert not STAGE.exists(),'Refuse existing Stage4 directory'
    STAGE.mkdir()
    for value in SPEC['child_writable_directories']:
        path=Path(value)
        path.mkdir()
        assert path.resolve()==path
    for key in ['DUNE_CACHE_ROOT','XDG_CACHE_HOME','XDG_CONFIG_HOME','CCACHE_DIR']:
        Path(SPEC['environment'][key]).mkdir(parents=True,exist_ok=True)
    Path(SPEC['environment']['XDG_RUNTIME_DIR']).mkdir(mode=0o700)
    assert stat.S_IMODE(Path(SPEC['environment']['XDG_RUNTIME_DIR']).stat().st_mode)==0o700

def copy_sources():
    (STAGE/'sources').mkdir()
    COPY.mkdir()
    for index,records in manifests():
        src=ROOT/'aeneas' if index==0 else ROOT/'aeneas/charon'
        dest=COPY if index==0 else COPY/'charon'
        if index==1:
            dest.mkdir()
        for item in records:
            tick()
            source=relative_path(src,item['path'])
            p=Path(item['path'])
            assert not p.is_absolute() and '..' not in p.parts
            parent=dest
            for part in p.parts[:-1]:
                parent=parent/part
                if not parent.exists():
                    parent.mkdir()
                assert parent.is_dir() and not parent.is_symlink(),str(parent)
            target=relative_path(dest,item['path'])
            assert not target.exists() and not target.is_symlink(),str(target)
            mode=source.lstat().st_mode
            if 'symlink' in item:
                assert stat.S_ISLNK(mode) and os.readlink(source)==item['symlink']
                target.symlink_to(item['symlink'])
            else:
                assert stat.S_ISREG(mode) and digest(source)==item['sha256']
                shutil.copy2(source,target,follow_symlinks=False)
                assert target.stat().st_nlink==1
    REPORT['copy_complete']=True
    persist()

def previous_receipt(name,expected_runner=None):
    path=STAGE/name
    data=json.loads(path.read_text())
    assert data.get('complete') is True and data['spec_sha256']==SPEC_HASH,str(path)
    assert data['runner_sha256']==(expected_runner or digest(Path(__file__))),str(path)
    return data,digest(path)

def verify_copy_patch():
    assert Path(SPEC['instrumentation_patch']['copied_target']).read_bytes()==expected_patched_bytes()
    for index,records in manifests():
        inventory(COPY if index==0 else COPY/'charon',records,patched=True)
    REPORT['copied_patch_sha256']=digest(Path(SPEC['instrumentation_patch']['copied_target']))
    persist()

def prepare():
    verify_installed_and_inputs('preflight')
    verify_sources('preflight')
    copy_sources()
    verify_sources('postcopy',check_copy=True,patched=False)
    verify_installed_and_inputs('postcopy')
    assert not Path(SPEC['build']['expected_executable']).exists()
    REPORT['prepared_unpatched_copy_only']=True

def verify_patch():
    previous,sha=previous_receipt('PREPARE_RECEIPT.json')
    assert previous.get('prepared_unpatched_copy_only') is True
    REPORT['prepare_receipt_sha256']=sha
    verify_installed_and_inputs('preflight')
    verify_sources('preflight',check_copy=True,patched=True)
    verify_copy_patch()
    assert not Path(SPEC['build']['expected_executable']).exists()
    REPORT['reviewed_instrumentation_only']=True

def parse_diagnostic(content):
    plain=re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]','',content)
    begin='SMZ9_STATIC_PROJ_DIAG_V1_BEGIN'
    end='SMZ9_STATIC_PROJ_DIAG_V1_END'
    assert plain.count(begin)==1 and plain.count(end)==1
    before,tail=plain.split(begin+'\n',1)
    block,after=tail.split(end+'\n',1)
    fields={}
    for line in block.splitlines():
        key,value=line.split('=',1)
        assert key not in fields
        fields[key]=value
    assert set(fields)==set(SPEC['instrumentation_patch']['output_fields'])
    booleans={}
    for key in SPEC['instrumentation_patch']['output_fields'][:4]:
        assert fields[key] in ['true','false']
        booleans[key]=fields[key]=='true'
    for key in SPEC['instrumentation_patch']['output_fields'][4:]:
        assert fields[key].startswith('"') and fields[key].endswith('"')
    assert 'interp/InterpProjectors.ml, line 125' in after
    assert 'apply_proj_borrows' in after
    assert 'evaluate_function_symbolic_synthesize_backward_from_return' in after
    assert not list((STAGE/'out/nodes').rglob('*.lean'))
    return {'booleans':booleans,'raw_ocaml_string_fields':fields,
            'hypothesis_boolean_pattern_matches':list(booleans.values())==[True,False,True,False],
            'raw_type_interpretation':'Pending human/root reading; observations are not forced to predicted booleans.'}

def revalidate_r3():
    # New R3 evidence, not relabeled R1 preparation receipts.
    old_prep,old_prep_sha=previous_receipt('PREPARE_RECEIPT.json',R1_RUNNER_SHA)
    old_patch,old_patch_sha=previous_receipt('PATCH_VERIFICATION.json',R1_RUNNER_SHA)
    assert old_prep.get('prepared_unpatched_copy_only') is True
    assert old_patch.get('reviewed_instrumentation_only') is True
    assert old_prep_sha=='7a15dd00a74d20c6149314de637f2874f91a5403e11e1991612bc9f9afa1c91e'
    assert old_patch_sha=='aa195d20d586b1c45e6613fe5dc4569b886bdf8638bfdb60fca22a40cd0a56d4'
    REPORT.update(prior_runner_sha256=R1_RUNNER_SHA,prior_prepare_receipt_sha256=old_prep_sha,
                  prior_patch_verification_sha256=old_patch_sha)
    verify_installed_and_inputs('revalidation')
    verify_sources('revalidation',check_copy=True,patched=True)
    verify_copy_patch()
    assert not Path(SPEC['build']['expected_executable']).exists()
    REPORT['r3_full_preflight_renewed']=True

def execute():
    # Root must approve this exact finalized runner hash before this mode is invoked.
    assert len(sys.argv)==3 and sys.argv[2]==digest(Path(__file__)),'Require reviewed runner SHA argument'
    renewed,renewed_sha=previous_receipt('R3_REVALIDATION.json')
    assert renewed.get('r3_full_preflight_renewed') is True
    REPORT['r3_revalidation_sha256']=renewed_sha
    verify_installed_and_inputs('preflight')
    verify_sources('preflight',check_copy=True,patched=True)
    verify_copy_patch()
    assert not Path(SPEC['build']['expected_executable']).exists()
    print('STAGE4 PREFLIGHT PASS; approved instrumentation-only build starts',flush=True)
    run('build',SPEC['build']['argv'],cwd=Path(SPEC['build']['cwd']),long=True)
    binary=Path(SPEC['build']['expected_executable'])
    assert binary.is_file()
    frozen=digest(binary)
    REPORT['instrumented_binary_sha256']=frozen
    run('binary-format',['/usr/bin/file',str(binary)])
    run('binary-linkage',['/usr/bin/otool','-L',str(binary)])
    for test in SPEC['tests']:
        assert digest(binary)==frozen
        content=run('test-'+test['name'],test['argv'],expected_exit=test['expected_exit'])
        if test['name']=='version':
            assert test['stdout_contains'] in content
        elif test['name']=='nodes-instrumented-original-assertion':
            REPORT['diagnostic']=parse_diagnostic(content)
            persist()
        else:
            assert 'SMZ9_STATIC_PROJ_DIAG' not in content
            destination=STAGE/'out'/test['name']
            found=sorted(str(p.relative_to(destination)) for p in destination.rglob('*') if p.is_file())
            expected=sorted(item['relative_path'] for item in test['files'])
            assert found==expected,(test['name'],found)
            for item in test['files']:
                assert digest(destination/item['relative_path'])==item['sha256']
        assert digest(binary)==frozen
    verify_sources('postflight',check_copy=True,patched=True)
    verify_installed_and_inputs('postflight')
    verify_copy_patch()
    REPORT.update(original_assertion_preserved=True,scalar_outputs_byte_identical=6,
                  semantic_patch_applied=False)

def main():
    global MODE,REPORT,REPORT_FILE,START,DEADLINE,LAST_SUCCESS
    assert sys.flags.optimize==0,'Do not disable Python assertions'
    assert len(sys.argv)>=2 and sys.argv[1] in ['revalidate-r3','execute']
    MODE=sys.argv[1]
    assert len(sys.argv)==(3 if MODE=='execute' else 2)
    START=time.time()
    DEADLINE=START+(30 if MODE=='execute' else 10)*60
    assert digest(SPEC_FILE)==SPEC_HASH
    assert PROFILE.read_text()==SPEC['sandbox_profile_text']
    filename={'revalidate-r3':'R3_REVALIDATION.json','execute':'R3_RECEIPT.json'}[MODE]
    assert not (STAGE/filename).exists(),'Never overwrite a retained phase receipt'
    assert STAGE.is_dir() and not STAGE.is_symlink()
    for value in SPEC['child_writable_directories']:
        path=Path(value)
        assert path.is_dir() and not path.is_symlink() and path.resolve()==path
    assert all(hasattr(os,name) for name in ['waitid','WNOWAIT','WEXITED','WNOHANG','P_PID'])
    REPORT_FILE=STAGE/filename
    REPORT={'scope':'Stage4 instrumentation only','mode':MODE,'spec_sha256':SPEC_HASH,
        'runner_sha256':digest(Path(__file__)),'started_utc':utc(),'started_epoch':START,
        'deadline_epoch':DEADLINE,'commands':[],'resource_samples':[],'transient_du_errors':[],
        'jobs':1,'environment_overrides':SPEC['environment']}
    try:
        resources()
        {'revalidate-r3':revalidate_r3,'execute':execute}[MODE]()
        resources()
        REPORT.update(complete=True,finished_utc=utc(),elapsed_seconds=time.time()-START)
        persist()
        print('STAGE4 '+MODE+' PASS',flush=True)
    except BaseException as exc:
        REPORT.update(complete=False,failure=repr(exc),stopped_utc=utc())
        persist()
        raise

if __name__=='__main__':
    main()
