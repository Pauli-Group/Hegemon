#!/usr/bin/env python3
"""Measure real block-timing windows for the swap deadline policy.

Read-only: fetches public block timestamps and prints, for several window sizes
k, the smallest and largest observed time spanned by k consecutive blocks. The
policy in config/swap/chain-timing.json embeds these tables. Rerun this script
and compare before changing a table; do not edit the numbers by hand.

Usage: python3 scripts/measure_chain_timing.py bitcoin-testnet4 2000
       python3 scripts/measure_chain_timing.py hegemon-pre-mainnet 3000
       python3 scripts/measure_chain_timing.py hegemon-pre-mainnet 3000 --update config/swap/chain-timing.json

With --update the measured tables and provenance replace `windows` and
`measurement` of the matching chain in the config; everything else is untouched.
"""
import json
import sys
import time
import urllib.request

WINDOWS = (1, 2, 3, 6, 12, 24, 48, 96, 144, 288)
UA = {'user-agent': 'Mozilla/5.0', 'accept': 'application/json'}


def get(url, tries=5):
    for attempt in range(tries):
        try:
            request = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except Exception:
            if attempt == tries - 1:
                raise
            time.sleep(2 + attempt * 3)


def bitcoin_testnet4(count):
    base = 'https://mempool.space/testnet4/api/blocks'
    out = {}
    cursor = None
    while len(out) < count:
        batch = get(base if cursor is None else f'{base}/{cursor}')
        if not batch:
            break
        for block in batch:
            out[block['height']] = block['timestamp']
        cursor = min(out) - 1
        time.sleep(0.7)
    return out


def hegemon(count):
    base = 'https://hegemon.pauli.group/testnet-api/v1/blocks?limit=50'
    out = {}
    before = None
    while len(out) < count:
        data = get(base if before is None else f'{base}&before={before}')
        if not data.get('blocks'):
            break
        for block in data['blocks']:
            out[block['height']] = block['timestamp_ms'] // 1000
        before = data.get('next_before')
        if before is None:
            break
        time.sleep(0.4)
    return out


OUTAGE_SECONDS = 7200


def tables(series, outage=OUTAGE_SECONDS):
    """Window tables over the series. A gap longer than `outage` seconds is an
    outage: windows containing it are excluded from the tables and the outage is
    listed. The policy adds an explicit outage allowance instead, so a stall that
    already happened cannot silently inflate or hide the normal-operation bounds."""
    heights = sorted(series)
    values = [series[h] for h in heights]
    gaps = [max(0, values[i + 1] - values[i]) for i in range(len(values) - 1)]
    outages = [
        {'after_height': heights[i], 'seconds': gaps[i]}
        for i in range(len(gaps)) if gaps[i] > outage
    ]
    result = {}
    for k in WINDOWS:
        spans = [
            max(0, values[i + k] - values[i])
            for i in range(len(values) - k)
            if max(gaps[i:i + k]) <= outage
        ]
        if spans:
            result[str(k)] = {'min': min(spans), 'max': max(spans), 'samples': len(spans)}
    normal = [g for g in gaps if g <= outage]
    return {
        'from_height': heights[0], 'to_height': heights[-1], 'blocks': len(heights),
        'mean_seconds': round(sum(normal) / len(normal), 2),
        'outage_threshold_seconds': outage,
        'outages': outages,
        'largest_gaps': sorted(gaps, reverse=True)[:5],
        'windows': result,
    }


CHAIN_KEYS = {'bitcoin-testnet4': 'bitcoin', 'hegemon-pre-mainnet': 'hegemon'}


def main():
    name, count = sys.argv[1], int(sys.argv[2])
    series = {'bitcoin-testnet4': bitcoin_testnet4, 'hegemon-pre-mainnet': hegemon}[name](count)
    report = tables(series)
    report['chain'] = name
    report['measured_at'] = int(time.time())
    if '--update' in sys.argv:
        path = sys.argv[sys.argv.index('--update') + 1]
        with open(path) as handle:
            config = json.load(handle)
        chain = config['chains'][CHAIN_KEYS[name]]
        chain['windows'] = {
            k: {'min': v['min'], 'max': v['max']}
            for k, v in sorted(report['windows'].items(), key=lambda item: int(item[0]))
        }
        chain['measurement'] = {key: report[key] for key in (
            'chain', 'measured_at', 'from_height', 'to_height', 'blocks', 'mean_seconds',
            'outage_threshold_seconds', 'outages', 'largest_gaps')}
        with open(path, 'w') as handle:
            json.dump(config, handle, indent=1)
            handle.write('\n')
    print(json.dumps(report, indent=1, sort_keys=True))


if __name__ == '__main__':
    main()
