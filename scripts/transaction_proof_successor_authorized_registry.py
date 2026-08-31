#!/usr/bin/env python3
"""Source-reviewed transaction-proof successor authorization records.

The exact tagged commit roots this file and the checker that loads it. A record
added here may pin one evidence bundle by path and SHA-512. The bundle must
never include this registry or the checker as evidence, which keeps the
authority graph one-way and avoids an impossible hash fixed point.

Keep this mapping empty until every release gate is independently satisfied.
Repository manifests and evidence bundles cannot add entries to it.
"""

AUTHORIZED_PROFILE_RECORDS = {}
