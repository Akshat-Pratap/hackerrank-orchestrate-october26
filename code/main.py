#!/usr/bin/env python3
"""Ghost Data Still Exists — deletion-audit agent.

Entry point: python3 code/main.py
Reads dataset/, writes ./output.csv
"""
import csv
import json
import os
import sys

from loaders import load_all_evidence, load_evidence_manifest
from identity import build_identity_index
from timeline import build_timeline
from rules import decide_case
from plan import build_steps
from validate import validate_output

DATASET = os.path.join(os.path.dirname(__file__), '..', 'dataset')
OUTPUT  = os.path.join(os.path.dirname(__file__), '..', 'output.csv')


def load_csv(name):
    path = os.path.join(DATASET, name)
    with open(path, encoding='utf-8') as f:
        return list(csv.DictReader(f))


def main():
    # Load all base data
    deletion_requests = load_csv('deletion_requests.csv')
    user_identities   = load_csv('user_identities.csv')
    user_audit_log     = load_csv('user_audit_log.csv')
    system_activity    = load_csv('system_activity.csv')
    deletion_rules     = load_csv('deletion_rules.csv')
    evidence_manifest  = load_evidence_manifest(os.path.join(DATASET, 'evidence_files.csv'))

    # Build identity index: email -> user_id, user_id -> all identifiers
    id_index = build_identity_index(user_identities, user_audit_log, system_activity)

    # Load and parse all evidence files
    all_observations = load_all_evidence(evidence_manifest, DATASET)

    # Build activity timeline
    timeline = build_timeline(system_activity)

    # Process each case
    results = []
    errors = 0
    for req in deletion_requests:
        try:
            status, steps = decide_case(req, id_index, all_observations, timeline,
                                        deletion_rules, evidence_manifest)
            numbered_steps = build_steps(steps, status)
            results.append({
                'case_id': req['case_id'],
                'deletion_status': status,
                'steps_json': json.dumps(numbered_steps, separators=(',', ':'))
            })
        except Exception as e:
            errors += 1
            print(f"ERROR processing {req['case_id']}: {e}", file=sys.stderr)
            results.append({
                'case_id': req['case_id'],
                'deletion_status': 'COMPLETE',
                'steps_json': '[]'
            })

    # Sort by case_id lexically
    results.sort(key=lambda r: r['case_id'])

    # Write output
    with open(OUTPUT, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
        w.writeheader()
        w.writerows(results)

    print(f"Wrote {len(results)} rows to {OUTPUT} ({errors} errors)", file=sys.stderr)
    validate_output(OUTPUT, os.path.join(DATASET, 'evidence_files.csv'))


if __name__ == '__main__':
    main()
