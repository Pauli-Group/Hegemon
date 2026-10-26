#!/usr/bin/env python3
"""Create a reviewable source-only patch against the frozen integration overlay.

Pass BASELINE_JSON OVERLAY_DIRECTORY OWNED_PATHS_JSON NEW_OUTPUT_DIRECTORY.
Owned paths is an explicit JSON array of repository-relative file names. The
script never stages/commits inherited changes and refuses wrong baseline hashes.
"""
import difflib
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import zipfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    if len(sys.argv) != 5:
        raise SystemExit(__doc__)
    baseline_path, overlay_dir, owned_path, output = map(Path, sys.argv[1:])
    baseline = json.loads(baseline_path.read_text())
    overlay = json.loads((overlay_dir / 'source-manifest.json').read_text())
    archive_path = overlay_dir / overlay['archive']
    if sha(archive_path.read_bytes()) != baseline['overlay_sha256']:
        raise SystemExit('Wrong overlay archive')
    if overlay['base_commit'] != baseline['base_commit']:
        raise SystemExit('Wrong base commit')
    scripting = baseline.get('scripting_bundle')
    scripting_manifest = None
    if scripting:
        scripting_dir = Path(scripting['directory'])
        manifest_bytes = (scripting_dir / 'manifest.json').read_bytes()
        if sha(manifest_bytes) != scripting['manifest_sha256']:
            raise SystemExit('Wrong scripting manifest')
        scripting_manifest = json.loads(manifest_bytes)
        scripting_archive = scripting_dir / 'source-delta.zip'
        if sha(scripting_archive.read_bytes()) != scripting['archive_sha256']:
            raise SystemExit('Wrong scripting archive')
        if scripting_manifest['ancestor_commit'] != baseline['base_commit'] or scripting_manifest['ancestor_overlay_sha256'] != baseline['overlay_sha256']:
            raise SystemExit('Wrong scripting ancestor')
    rows = {row['path']: row for row in baseline['files']}
    paths = json.loads(owned_path.read_text())
    if len(paths) != len(set(paths)):
        raise SystemExit('Duplicate owned path')
    output.mkdir(exist_ok=False)
    patch = []
    changed = []
    with ExitStack() as stack:
        archive = stack.enter_context(zipfile.ZipFile(archive_path))
        scripting_zip = stack.enter_context(zipfile.ZipFile(scripting_archive)) if scripting else None
        scripting_rows = {row['path']: row for row in scripting_manifest['files']} if scripting else {}
        if scripting:
            for row in scripting_rows.values():
                if sha(scripting_zip.read('incoming/' + row['path'])) != row['incoming_sha256']:
                    raise SystemExit('Wrong scripting source image: ' + row['path'])
        scratch = stack.enter_context(tempfile.TemporaryDirectory(prefix='hegemon-asset-patch-'))
        scratch = Path(scratch)
        archived = set(archive.namelist())
        for name in sorted(paths):
            relative = PurePosixPath(name)
            if relative.is_absolute() or '..' in relative.parts or name.startswith(('target', '.git/', '.agent/')):
                raise SystemExit('Unsafe/source-excluded owned path: ' + name)
            current = Path(name)
            if current.is_symlink() or not current.is_file():
                raise SystemExit('Expected regular current source: ' + name)
            after = current.read_bytes()
            if name in scripting_rows:
                before = scripting_zip.read('incoming/' + name)
            elif name in archived:
                before = archive.read(name)
            else:
                found = subprocess.run(['git', 'show', baseline['base_commit'] + ':' + name], capture_output=True, check=False)
                before = found.stdout if found.returncode == 0 else None
            expected = rows.get(name)
            if (before is None) != (expected is None) or (before is not None and sha(before) != expected['sha256']):
                raise SystemExit('Baseline preimage mismatch: ' + name)
            if before == after:
                continue
            if before is not None:
                target = scratch / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(before)
            patch.extend(difflib.unified_diff(
                (before or b'').decode().splitlines(keepends=True),
                after.decode().splitlines(keepends=True),
                fromfile='a/' + name if before is not None else '/dev/null',
                tofile='b/' + name,
            ))
            changed.append({'path': name, 'preimage_sha256': sha(before) if before is not None else None,
                            'postimage_sha256': sha(after), 'bytes': len(after)})
        patch_path = (output / 'stablecoin-only.patch').resolve()
        patch_path.write_text(''.join(patch))
        # An independent Git patch parser validates both preimages and results
        # against a small reconstructed baseline, without an index or checkout.
        subprocess.run(['git', 'apply', '--check', str(patch_path)], cwd=scratch, check=True)
        subprocess.run(['git', 'apply', str(patch_path)], cwd=scratch, check=True)
        for row in changed:
            if sha((scratch / row['path']).read_bytes()) != row['postimage_sha256']:
                raise SystemExit('Applied postimage mismatch: ' + row['path'])
    manifest = {'schema': 'hegemon.stablecoin.additive-patch.v1', 'base_commit': baseline['base_commit'],
                'overlay_sha256': baseline['overlay_sha256'], 'baseline_manifest_sha256': sha(baseline_path.read_bytes()),
                'patch_sha256': sha(patch_path.read_bytes()), 'validated_git_apply': True, 'files': changed}
    if scripting:
        manifest['scripting_manifest_sha256'] = scripting['manifest_sha256']
        manifest['scripting_archive_sha256'] = scripting['archive_sha256']
    (output / 'patch-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'changed_files': len(changed), 'patch_sha256': manifest['patch_sha256'], 'git_apply': 'passed'}))


if __name__ == '__main__':
    main()
