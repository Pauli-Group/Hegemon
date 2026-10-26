#!/usr/bin/env python3
"""Check an honest RP05 assumption ledger; this does not prove cryptography."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
LEDGER = Path('docs/crypto/rp05_primitive_assumptions.json')
EXPECTED = {
    'epsilonNoteCommitment': ('currentHistoryGenesisPathNoteCommitmentGameEvent', 'exactV8NoteCommitment'),
    'epsilonMerkle': ('currentHistoryGenesisPathMerkleCompressionGameEvent', 'merkleCompress14Evaluator'),
    'epsilonNullifier': ('nullifierPrimitiveEvent', 'nullifierOutput'),
    'epsilonSingle': ('singleKeyPrimitiveEvent', 'singleKeyEvaluator'),
    'epsilonAccumulator': ('accumulatorPrimitiveEvent', 'accumulatorCompress14Evaluator'),
    'epsilonMixed': ('mixedClawPrimitiveEvent', 'mixedDomainEvaluator'),
}
BOUNDARIES = {'sha512_qrom', 'ciphertext_projection_binding', 'blake2b_interpretation',
              'rust_parser_verifier', 'adaptive_context_extraction', 'encryption_authentication_rng'}
DOMAINS = {'epsilonNoteCommitment': '1', 'epsilonMerkle': '4',
           'epsilonNullifier': '0x484e554c56320001',
           'epsilonSingle': '0x48534b4156320001',
           'epsilonAccumulator': '0x484d424456320001',
           'epsilonMixed': ['0x48534b4156320001', '0x484d424456320001']}
BOUNDARY_STATUS = {'sha512_qrom': 'ideal_quantum_random_oracle_model',
    'ciphertext_projection_binding': 'unquantified_external_assumption',
    'blake2b_interpretation': 'implementation_refinement_unproved',
    'rust_parser_verifier': 'implementation_refinement_unproved',
    'adaptive_context_extraction': 'not_closed',
    'encryption_authentication_rng': 'separate_product_assumptions'}


def unique_object(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError('duplicate JSON key: ' + k)
        out[k] = v
    return out


def regular(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or '\\' in relative:
        raise ValueError('invalid repository-relative evidence path')
    q = PurePosixPath(relative)
    if q.is_absolute() or q.as_posix() != relative or any(x in ('', '.', '..') for x in relative.split('/')):
        raise ValueError('noncanonical evidence path')
    p = root
    for part in q.parts:
        p = p / part
        if p.is_symlink():
            raise ValueError('symlink evidence path')
    if not p.is_file() or not p.resolve().is_relative_to(root.resolve()):
        raise ValueError('missing/escaped evidence path')
    return p


def validate(root: Path, d: dict, require_quantified: bool = False) -> dict:
    if d.get('schema') != 'hegemon.rp05.primitive-assumptions.v1':
        raise ValueError('unsupported ledger schema')
    if d.get('status') != 'AUDITED_CONDITIONAL_UNQUANTIFIED':
        raise ValueError('unquantified audit status changed')
    if d.get('production_authorized') is not False or d.get('unconditional_128_bit_security') is not False:
        raise ValueError('ledger must not grant production or unconditional security authority')
    if d.get('primitive_query_cap_inferred_from_proof_cap') is not False:
        raise ValueError('proof-oracle cap does not imply a primitive adversary resource bound')
    if d.get('proof_oracle_query_cap') != '3*2^64':
        raise ValueError('proof-model query cap changed; re-audit required')
    texts = {}
    for e in d.get('evidence', []):
        if e.get('id') in texts:
            raise ValueError('duplicate evidence ID')
        p = regular(root, e['path'])
        raw = p.read_bytes()
        if hashlib.sha256(raw).hexdigest() != e.get('sha256'):
            raise ValueError('stale evidence: ' + e['path'])
        texts[e['id']] = raw.decode('utf-8')
    suite = d.get('primitive_suite', {})
    expected_suite = {'parameter_set_id': 'hegemon-p2w16-v1-114a4e7eb2684d29',
        'width': 16, 'sponge_rate': 8, 'sponge_capacity': 8, 'sbox_degree': 7,
        'full_rounds': 8, 'partial_rounds': 22, 'digest_field_words': 7,
        'parameter_review_status': 'candidate_external_review_required',
        'parameter_production_authorized': False,
        'generic_work_or_reduced_round_screen_is_concrete_advantage_bound': False,
        'evidence_ids': ['parameter_manifest', 'rust_permutation', 'lean_permutation', 'semantic']}
    if suite != expected_suite or any(i not in texts for i in suite['evidence_ids']):
        raise ValueError('primitive suite/review boundary changed')
    params = json.loads(texts['parameter_manifest'], object_pairs_hook=unique_object)
    geometry = params.get('parameters', {})
    if any(geometry.get(k) != v for k, v in {'width': 16, 'rate': 8, 'capacity': 8,
            'sbox_degree': 7, 'full_rounds': 8, 'partial_rounds': 22,
            'digest_field_elements': 7}.items()):
        raise ValueError('pinned parameter tuple differs from audited suite')
    if (params.get('parameter_set_id') != suite['parameter_set_id']
            or params.get('production_authorized') is not False
            or params.get('required_external_review') is not True
            or params.get('review_status') != suite['parameter_review_status']
            or params.get('security', {}).get('composed_pq128_soundness_established') is not False
            or params.get('digests', {}).get('source_sha256') !=
               hashlib.sha256(texts['rust_permutation'].encode()).hexdigest()):
        raise ValueError('parameter source/review boundary changed')
    terms = d.get('terms', [])
    if len(terms) != 6 or {t.get('name') for t in terms} != set(EXPECTED):
        raise ValueError('the exact six distinct advantage terms are required')
    for t in terms:
        if (t.get('event'), t.get('primitive')) != EXPECTED[t['name']]:
            raise ValueError('event/evaluator binding changed: ' + t['name'])
        if t.get('domain') != DOMAINS[t['name']] or t.get('game') != (
                'cross-domain-claw' if t['name'] == 'epsilonMixed' else 'collision'):
            raise ValueError('domain/game binding changed: ' + t['name'])
        if any(t.get(k) != 'mechanized' for k in
               ('pointwise_game_mapping', 'same_outcome_mass_composition')):
            raise ValueError('reviewed game-mapping status changed')
        ids = t.get('evidence_ids', [])
        if not ids or any(i not in texts for i in ids):
            raise ValueError('missing term evidence')
        for symbol in EXPECTED[t['name']]:
            if not any(re.search(r'\b(?:def|abbrev|theorem)\s+' + re.escape(symbol) + r'\b', texts[i]) for i in ids):
                raise ValueError('declared symbol missing from exact evidence: ' + symbol)
        if t.get('output') != {'field_modulus': 18446744069414584321, 'field_words': 7}:
            raise ValueError('primitive output geometry changed')
        if t.get('concrete_advantage_bound') is not None or t.get('primitive_resource_budget') is not None:
            raise ValueError('concrete bounds need a reviewed computational reduction and evidence schema')
        if t.get('numerical_security_status') != 'unquantified_external_assumption':
            raise ValueError('unquantified advantage must remain explicitly unquantified')
        if t.get('standalone_efficient_quantum_reduction') != 'not_established_by_these_endpoints':
            raise ValueError('standalone reduction closure requires separate reviewed evidence')
    extra = d.get('additional_boundaries', [])
    if len(extra) != len(BOUNDARIES) or {e.get('id') for e in extra} != BOUNDARIES:
        raise ValueError('separate model/implementation/product boundaries are incomplete')
    if any(not e.get('evidence_ids') or any(i not in texts for i in e['evidence_ids']) for e in extra):
        raise ValueError('missing additional-boundary evidence')
    if any(e.get('status') != BOUNDARY_STATUS[e['id']] for e in extra):
        raise ValueError('additional boundary closure needs separate reviewed evidence')
    b = d.get('sufficient_six_term_budget', {})
    if b.get('aggregate') != '3/2^130' or b.get('equal_allocation_per_term') != '1/2^131' or b.get('covers_additional_assumptions') is not False:
        raise ValueError('incorrect/incomplete arithmetic budget labeling')
    if require_quantified:
        raise ValueError('release-level quantified primitive assumptions remain open: all six bounds are unquantified')
    return {'status': 'PASS_AUDIT_INTEGRITY', 'terms': 6, 'concrete_bounds': 0,
            'standalone_quantum_reductions_closed': 0,
            'security_claim': 'conditional model result only', 'production_authorized': False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['check'])
    p.add_argument('--root', type=Path, default=ROOT)
    p.add_argument('--require-quantified', action='store_true')
    a = p.parse_args()
    raw = regular(a.root, LEDGER.as_posix()).read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError('ledger too large')
    d = json.loads(raw, object_pairs_hook=unique_object,
                   parse_constant=lambda x: (_ for _ in ()).throw(ValueError('non-finite JSON')))
    print(json.dumps(validate(a.root, d, a.require_quantified)))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as e:
        print('FAIL RP05 primitive ledger: ' + str(e), file=sys.stderr)
        sys.exit(1)
