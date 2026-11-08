# Bitcoin Cash ASERT reference vectors

These byte-exact files are published by Bitcoin Cash Node and linked by the official
ASERT specification. They exercise the BCH 600-second spacing, 172800-second half-life,
and 0x1d00ffff target limit, not Hegemon activation policy or its chosen parameters.

Source: https://download.bitcoincashnode.org/misc/data/asert/test_vectors/
Specification: https://bitcoin-cash-node.gitlab.io/bchn-sw/bitcoincash-upgrade-specifications/2020-11-15-asert/
Reference implementation: https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/master/src/pow.cpp
Fetched: 2026-10-29. The SHA-256 hashes below pin the exact bytes.

The upstream headers use "anchor ancestor time" in runs 01-10 and "anchor parent
time" in runs 11-12; both refer to the parent of the anchor block. The test parser
accepts both original labels without changing the downloaded files.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| run01 | 441 | bfdbac6a3eb2ffaeecb8475ab7be4de61b780f1abc2ad858846a44d69d4a496e |
| run02 | 462 | 0db6f9bc26a3bb29a06ea2dec44606803c76aca8b903de0658e1cd40c00efc7d |
| run03 | 456 | a21049dca0426086d4bc399ad962861e7e032f22a89e0bf7da8d0e1f99c7b790 |
| run04 | 6314 | 3d195813853c758920d49ce54e0d2048b5dbf66264d669a200c0b5b66138e025 |
| run05 | 5328 | 02d8a492d91f166fad424391830f8921de650f9820483300f8c90ba72a67238a |
| run06 | 25895 | 12a0f7672327cf8887367cf93ed22c36ae1c3778352e922de771af15496812fe |
| run07 | 25066 | 8dae763a095cfe8ab6721e0bad23d433a4596ed8b0a9d9db9bc551c73be64111 |
| run08 | 13336 | 7d19ee783dea42989d4a2d3ddf475a8c26e1f31fc1b517d348a4e3f7e6ec8403 |
| run09 | 649 | 430d771c8c6c853e0aa8190e049826add47f517dfb9898a2bf0b5c7a3280c717 |
| run10 | 794 | 34dff0a33085043626be6f1290a4089e18bd037010084b37bc67f14141121621 |
| run11 | 25679 | f912d4fb2edcf65037fa7e8c279c49a291e8e74ce507b15b3478146fe653ad88 |
| run12 | 259243 | 897418f85dcb17814ea7b7556547565271c524723ece8af8d47fab4bdc0ab179 |

Total: 14000 expected target computations. These are interoperability regressions,
not a proof that the implementation or the network upgrade is correct.
