#!/usr/bin/env python3
"""Run pipeline on sample cases and score against sample_output.csv."""
import csv
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from loaders import load_all_evidence, load_evidence_manifest
from identity import build_identity_index
from timeline import build_timeline
from rules import decide_case
from plan import build_steps

DATASET = os.path.join(os.path.dirname(__file__), '..', '..', 'dataset')
SAMPLE_OUTPUT = os.path.join(DATASET, 'sample_output.csv')


def load_csv(name):
    path = os.path.join(DATASET, name)
    with open(path, encoding='utf-8') as f:
        return list(csv.DictReader(f))


def main():
    # Load base data
    sample_requests = load_csv('sample_deletion_requests.csv')
    user_identities = load_csv('user_identities.csv')
    user_audit_log = load_csv('user_audit_log.csv')
    system_activity = load_csv('system_activity.csv')
    deletion_rules = load_csv('deletion_rules.csv')
    evidence_manifest = load_evidence_manifest(os.path.join(DATASET, 'evidence_files.csv'))

    id_index = build_identity_index(user_identities, user_audit_log, system_activity)
    all_observations = load_all_evidence(evidence_manifest, DATASET)
    timeline = build_timeline(system_activity)

    # Process sample cases
    results = {}
    for req in sample_requests:
        status, steps = decide_case(req, id_index, all_observations, timeline,
                                    deletion_rules, evidence_manifest)
        numbered_steps = build_steps(steps, status)
        results[req['case_id']] = {
            'deletion_status': status,
            'steps': numbered_steps,
        }

    # Load truth
    with open(SAMPLE_OUTPUT, encoding='utf-8') as f:
        truth = {r['case_id']: r for r in csv.DictReader(f)}

    # Score
    sample_ids = sorted(truth.keys())
    total = len(sample_ids)
    status_correct = 0
    step_exact = 0

    for cid in sample_ids:
        t = truth[cid]
        t_status = t['deletion_status']
        t_steps = json.loads(t['steps_json'])

        p = results.get(cid)
        if p is None:
            print(f"{cid}: MISSING from predictions")
            continue

        p_status = p['deletion_status']
        p_steps = p['steps']

        sc = t_status == p_status
        if sc:
            status_correct += 1

        seq = t_steps == p_steps
        if seq:
            step_exact += 1

        if not sc or not seq:
            print(f"\n{cid}: status={p_status} (exp={t_status}) {'OK' if sc else 'WRONG'}")
            if not seq:
                t_set = set()
                p_set = set()
                for s in t_steps:
                    t_set.add((s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'], s.get('evidence_id', '')))
                for s in p_steps:
                    p_set.add((s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'], s.get('evidence_id', '')))

                missing = t_set - p_set
                extra = p_set - t_set
                if missing:
                    print(f"  missing({len(missing)}):")
                    for m in sorted(missing)[:5]:
                        print(f"    {m}")
                if extra:
                    print(f"  extra({len(extra)}):")
                    for e in sorted(extra)[:5]:
                        print(f"    {e}")

    print(f"\n=== Status: {status_correct}/{total} ({100*status_correct/total:.1f}%) ===")
    print(f"=== Exact: {step_exact}/{total} ({100*step_exact/total:.1f}%) ===")


if __name__ == '__main__':
    main()
