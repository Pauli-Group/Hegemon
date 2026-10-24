# Immutable v0.11 predecessor evidence

These chunks preserve the exact source-qualification dependency closure and the
registered macOS final-artifact-phase dependencies from the qualified predecessor.
They do not authorize new source, new binary hashes, deployment, or a network
cutover. Linux final qualification is a separate retained package.

The materializer pins the manifest SHA256 in reviewed source, verifies every
compressed part, extracts only the declared regular files, and verifies their
size, digest and portable metadata. It rejects links, traversal, unexpected or
duplicate files, Windows device paths, case collisions, excessive PAX metadata
and expansion beyond the declared bound. Existing restored data is reused only
after exact verification; mismatches are never overwritten.

From the repository root:

```sh
python3 -I -B scripts/test_materialize_v011_predecessor.py
python3 -I -B scripts/materialize_v011_predecessor.py
python3 -I -B target/v011-predecessor/scripts/check_private_spend_launch_authorization.py --require-authorized
```

The default destination is `target/v011-predecessor`; the default free-space
reserve is 15 GiB. Disposable hosted CI may explicitly use
`--reserve-bytes 4294967296` to retain a 4 GiB reserve. No network access or
external Python packages are required. Restored compiled objects and binaries
are hashed as retained evidence; the source check does not execute them.

The archive contains 3,058 files totaling 837,909,361 bytes. The deterministic
PAX tar stream is 841,861,120 bytes; gzip is 278,177,589 bytes in seven parts,
each at most 40 MiB. No expanded source/evidence or native binaries are stored
in Git.

Reproduction uses the manifest's sorted file rows from an exact restored tree:
Python `tarfile.PAX_FORMAT`, ordinary regular entries only, each recorded mode
and size, uid/gid/mtime zero and empty uname/gname. Stream the tar through
`gzip.GzipFile(filename="", mode="wb", mtime=0, compresslevel=6)`, and split the
compressed bytes at 41,943,040-byte boundaries. The complete compressed SHA256
is `c2f2ec5d98e14c3abe5ed0db3438afd91725f4be106a923ca1f0f2c6a489876f`.
The exact full reconstruction from the restored tree reproduced all seven
part digests without reading the original worktree.

`TRANSPORT-VALIDATION.json` records bounded local transport checks. It grants
no cryptographic, implementation-equivalence or release authority.
