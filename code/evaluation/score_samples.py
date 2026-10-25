#!/usr/bin/env python3
"""Score pipeline against sample_output.csv. Reports 01-06 and 07-32 separately."""
import csv
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from loaders import load_all_evidence, load_evidence_manifest
from identity import build_identity_index
from main import (load_csv, DATASET, CACHE_DIR, _decide, _number_steps, _build_account_cluster_map)
from collections import defaultdict

SAMPLE_OUTPUT = os.path.join(DATASET, 'sample_output.csv')


def run_and_score():
    user_identities = load_csv('user_identities.csv')
    user_audit_log = load_csv('user_audit_log.csv')
    system_activity = load_csv('system_activity.csv')
    evidence_manifest = load_evidence_manifest(os.path.join(DATASET, 'evidence_files.csv'))
    sample_requests = load_csv('sample_deletion_requests.csv')

    id_index = build_identity_index(user_identities, user_audit_log, system_activity)
    all_observations = load_all_evidence(evidence_manifest, DATASET, CACHE_DIR)

    obs_by_resource = defaultdict(list)
    obs_by_user = defaultdict(list)
    obs_by_email = defaultdict(list)
    for file_id, obs_list in all_observations.items():
        for ob in obs_list:
            obs_by_resource[ob['resource_id']].append(ob)
            ids = ob.get('identifiers', {})
            if ids.get('user_id'):
                obs_by_user[ids['user_id']].append(ob)
            if ids.get('email'):
                obs_by_email[ids['email']].append(ob)
            if ids.get('lookup_key'):
                obs_by_email[ids['lookup_key']].append(ob)
            if ids.get('email_hash'):
                obs_by_email[ids['email_hash']].append(ob)

    activity_by_resource = defaultdict(list)
    for act in system_activity:
        activity_by_resource[act['resource_id']].append(act)
    for k in activity_by_resource:
        activity_by_resource[k].sort(key=lambda a: a['event_time'])

    account_cluster_map = _build_account_cluster_map(sample_requests, system_activity, id_index)
    classify_requests = {act['resource_id']: act['event_time']
                         for act in system_activity if act['event_type'] == 'CLASSIFY_REQUEST'}
    manifest_by_time = sorted(evidence_manifest.values(), key=lambda e: e['captured_at'])

    with open(SAMPLE_OUTPUT, encoding='utf-8') as f:
        truth = {r['case_id']: r for r in csv.DictReader(f)}

    results = {}
    for req in sample_requests:
        cid = req['case_id']
        status, steps = _decide(
            req, id_index, obs_by_resource, obs_by_user, obs_by_email,
            activity_by_resource, account_cluster_map,
            classify_requests=classify_requests, manifest_by_time=manifest_by_time)
        numbered = _number_steps(steps, status)
        results[cid] = (status, numbered)

    # Score separately for 01-06 and 07-32
    groups = {
        '01-06': [c for c in truth if int(c.replace('case_', '')) <= 6],
        '07-32': [c for c in truth if int(c.replace('case_', '')) >= 7],
    }

    for grp_name, cids in groups.items():
        cids = sorted(cids)
        total = len(cids)
        status_ok = 0
        exact_ok = 0
        diffs = []

        for cid in cids:
            t = truth[cid]
            t_status = t['deletion_status']
            t_steps = json.loads(t['steps_json'])

            p_status, p_steps = results.get(cid, ('MISSING', []))

            sc = t_status == p_status
            if sc:
                status_ok += 1

            seq = t_steps == p_steps
            if seq:
                exact_ok += 1

            if not sc or not seq:
                t_set = set()
                p_set = set()
                for s in t_steps:
                    t_set.add((s['phase'], s['system_id'], s['resource_id'], s['operation'], s.get('evidence_id', '')))
                for s in p_steps:
                    p_set.add((s['phase'], s['system_id'], s['resource_id'], s['operation'], s.get('evidence_id', '')))
                miss = t_set - p_set
                extra = p_set - t_set
                diffs.append((cid, t_status, p_status, miss, extra))

        print('\n=== Group %s (%d cases) ===' % (grp_name, total))
        print('Status: %d/%d (%.0f%%)' % (status_ok, total, 100 * status_ok / total))
        print('Exact:  %d/%d (%.0f%%)' % (exact_ok, total, 100 * exact_ok / total))

        if diffs:
            print('Diffs (%d):' % len(diffs))
            for cid, ts, ps, miss, extra in diffs[:8]:
                print('  %s exp=%s got=%s' % (cid, ts, ps))
                for m in sorted(miss)[:3]:
                    print('    MISS:', m[0][:4], m[1], m[2], m[3][:25], m[4])
                for e in sorted(extra)[:2]:
                    print('    XTRA:', e[0][:4], e[1], e[2], e[3][:25], e[4])


if __name__ == '__main__':
    run_and_score()
