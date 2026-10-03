#!/usr/bin/env python3
"""Bounded development feedback, not final formal/release qualification."""
import ast
import datetime
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time

CONTROL = Path('/private/tmp/smz9-prod-hour.QgQPJ8Pk')
GUARD = Path('/private/tmp/smz9-aeneas-stage1.IgNKumAA/run_stage4_instrumentation_r3.py')
GUARD_SHA = '8dfa95252ded2640ace88b025cad1eb087499ca4e145866cddec338656edb305'
# User explicitly resumed after the prior session cutoff. Per-command 250/300s limits remain.
HARD_STOP = time.time() + 600
ACTIVE_GROUPS = {}
ENV = {}

def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def census(root, mutable):
    for attempt in range(3):
        try:
            total = 0
            for directory, dirs, files in os.walk(root, followlinks=False,
                                                   onerror=lambda e: (_ for _ in ()).throw(e)):
                for path in [Path(directory)] + [Path(directory)/n for n in files]:
                    info = path.lstat()
                    assert stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), path
                    total += info.st_blocks * 512
                for name in dirs:
                    assert not (Path(directory)/name).is_symlink(), name
            return total
        except FileNotFoundError as error:
            missing = Path(error.filename or '')
            if (error.errno != errno.ENOENT or not missing.is_absolute()
                    or '..' in missing.parts or str(missing) != error.filename
                    or not any(missing.is_relative_to(p) for p in mutable) or attempt == 2):
                raise

def run(config_path, name):
    global ENV
    config_path = Path(config_path).resolve(strict=True)
    spec = json.loads(config_path.read_text())
    if isinstance(spec['inputs'], list):
        pins = spec['inputs']
        spec['inputs'] = {p['path']:p['sha256'] for p in pins}
        assert len(spec['inputs']) == len(pins), 'Duplicate input pins'
    spec.setdefault('child_writable', ['build','cache','tmp','out'])
    root = Path(spec['root'])
    assert root.is_absolute() and root.resolve(strict=True) == root
    assert root.is_relative_to('/private/tmp') and root != Path('/private/tmp')
    command = next(c for c in spec['commands'] if c['name'] == name)
    assert sum(c['name'] == name for c in spec['commands']) == 1
    assert name.replace('-', '').replace('_', '').isalnum()
    output = root/'out'/('dev-'+name)
    output.mkdir(parents=True, exist_ok=False)
    limits = spec['limits']
    assert limits['wall_seconds'] <= 300 and limits['child_stop_seconds'] <= 250
    assert limits['peak_rss_bytes'] <= 8*1024**3
    assert limits['stop_group_rss_bytes'] <= limits['peak_rss_bytes']-256*1024**2
    assert limits['scratch_bytes'] <= 1024**3
    assert limits['stop_scratch_bytes'] < limits['scratch_bytes']
    assert limits['minimum_free_bytes'] >= 20*1024**3
    assert limits['max_sample_gap_seconds'] <= 5
    assert time.time()+limits['wall_seconds'] < HARD_STOP
    ENV = spec['environment']
    assert command['argv'][:2] == ['/usr/bin/sandbox-exec', '-f']
    report = {'purpose':'development-only', 'production_authorized':False,
              'config_sha256':sha(config_path), 'command':command, 'samples':[]}
    report_path = output/'receipt.json'
    def persist():
        report_path.write_text(json.dumps(report, indent=2)+'\n')
    def inputs():
        result = {p:sha(p) for p in spec['inputs']}
        assert result == spec['inputs'], 'Development source input changed'
        return result
    start = time.monotonic()
    last_sample = [start]
    stop_watchdog = threading.Event()
    group = None
    watcher = None
    def watch():
        while not stop_watchdog.wait(0.1):
            now = time.monotonic()
            if (now-start >= limits['child_stop_seconds']
                    or now-last_sample[0] > limits['max_sample_gap_seconds']
                    or time.time() >= HARD_STOP-20):
                report['watchdog_stop'] = {'elapsed':now-start, 'sample_gap':now-last_sample[0]}
                group._kill_watchdog()
                return
    def sample(active=None):
        before = time.monotonic()
        row = {'elapsed':before-start,
               'scratch_allocated_bytes':census(root, [root/p for p in spec['child_writable']]),
               'free_bytes':shutil.disk_usage(root).free,
               'waited_children_peak_rss_bytes':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}
        if active is not None:
            ps = subprocess.run(['/bin/ps','-p',str(active.proc.pid),'-g',str(active.pgid),
                                 '-o','pid=,pgid=,rss='],env=ENV,text=True,
                                capture_output=True,check=True,timeout=0.2)
            rows = [[int(x) for x in line.split()] for line in ps.stdout.splitlines()]
            assert any(r[0] == active.proc.pid for r in rows)
            assert all(r[1] == active.pgid for r in rows)
            row['owned_group_rss_bytes'] = sum(r[2]*1024 for r in rows)
        completed = time.monotonic()
        row['completed_sample_gap_seconds'] = completed-last_sample[0]
        report['samples'].append(row)
        persist()  # Preserve the triggering row, including failed samples.
        assert row['free_bytes'] >= limits['minimum_free_bytes'], 'Disk headroom stop'
        assert row['scratch_allocated_bytes'] < limits['stop_scratch_bytes'], 'Scratch stop'
        assert row['waited_children_peak_rss_bytes'] < limits['peak_rss_bytes'], 'Waited RSS stop'
        assert row.get('owned_group_rss_bytes',0) < limits['stop_group_rss_bytes'], 'Group RSS stop'
        assert row['completed_sample_gap_seconds'] <= limits['max_sample_gap_seconds'], 'Sample gap stop'
        assert completed-start < limits['wall_seconds'], 'Whole-attempt time stop'
        if active is not None:
            assert completed-start < limits['child_stop_seconds'], 'Child time stop'
        last_sample[0] = completed
    try:
        report['preflight_inputs'] = inputs()
        sample()
        item = report['execution'] = {}
        group = ChildProcessGroup(item)
        proc = None
        with (output/'command.log').open('xb') as log:
            try:
                proc = subprocess.Popen(command['argv'],cwd=spec['cwd'],env=ENV,
                                        stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                group.attach(proc)
                watcher = threading.Thread(target=watch,daemon=True)
                watcher.start()
                group.initialize_metadata()
                while not group.leader_exited():
                    sample(group)
                    time.sleep(0.1)
                stop_watchdog.set()
                watcher.join(timeout=1)
                assert not watcher.is_alive()
                group.finish()
            except BaseException:
                stop_watchdog.set()
                try:
                    if watcher is not None and watcher.ident is not None:
                        watcher.join(timeout=1)
                finally:
                    if proc is not None:
                        if group.proc is None:
                            group.attach(proc)
                        if not group.retired:
                            group.finish(terminate=True)
                raise
        report['exit_code'] = proc.returncode
        assert proc.returncode == 0, 'Command returned nonzero'
        assert not group.kill_event.is_set() and not item.get('watchdog_errors')
        report['postflight_inputs'] = inputs()
        sample()
        report['status'] = 'PASS_DEVELOPMENT_ONLY'
    except BaseException as error:
        report['status'] = 'FAILED'
        report['error'] = repr(error)
    finally:
        report['elapsed_seconds'] = time.monotonic()-start
        report['active_reservations'] = list(ACTIVE_GROUPS)
        log_path = output/'command.log'
        if log_path.exists():
            report['log_sha256'] = sha(log_path)
        persist()
    print(json.dumps({'status':report['status'],'receipt':str(report_path),
                      'sha256':sha(report_path),'error':report.get('error')}),flush=True)
    return 0 if report['status'] == 'PASS_DEVELOPMENT_ONLY' else 1

if __name__ == '__main__':
    assert sha(GUARD) == GUARD_SHA
    tree = ast.parse(GUARD.read_text())
    classes = [n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='ChildProcessGroup']
    assert len(classes)==1
    exec(compile(ast.Module(body=classes,type_ignores=[]),str(GUARD),'exec'),globals())
    with (CONTROL/'lane.lock').open('a') as lane:
        fcntl.flock(lane,fcntl.LOCK_EX|fcntl.LOCK_NB)
        sys.exit(run(sys.argv[1],sys.argv[2]))
