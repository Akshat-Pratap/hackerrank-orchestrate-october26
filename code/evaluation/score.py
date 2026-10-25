#!/usr/bin/env python3
"""Scorer: compare pipeline output against sample_output.csv (32 cases)."""
import csv
import json
import os
import sys

DATASET = os.path.join(os.path.dirname(__file__), '..', '..', 'dataset')


def load_sample_output():
    path = os.path.join(DATASET, 'sample_output.csv')
    with open(path, encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    return {r['case_id']: r for r in rows}


def load_predicted(path):
    with open(path, encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    return {r['case_id']: r for r in rows}


def score(predicted_path=None):
    if predicted_path is None:
        predicted_path = os.path.join(os.path.dirname(__file__), '..', '..', 'output.csv')

    truth = load_sample_output()
    pred = load_predicted(predicted_path)

    sample_ids = sorted(truth.keys())
    total = len(sample_ids)

    status_correct = 0
    step_exact_match = 0
    step_total_expected = 0
    step_total_predicted = 0
    step_match = 0

    field_counts = {}
    field_correct = {}
    for field in ['system_id', 'resource_id', 'operation', 'state', 'evidence_id']:
        field_counts[field] = 0
        field_correct[field] = 0

    worst_diffs = []

    for cid in sample_ids:
        t = truth[cid]
        p = pred.get(cid)

        if p is None:
            worst_diffs.append((cid, 'MISSING', '', ''))
            continue

        t_status = t['deletion_status']
        p_status = p['deletion_status']

        if t_status == p_status:
            status_correct += 1

        t_steps = json.loads(t['steps_json'])
        p_steps = json.loads(p['steps_json'])

        # Exact sequence match
        if t_steps == p_steps:
            step_exact_match += 1
        else:
            # Compute diff
            diff_desc = _compute_diff(cid, t_status, p_status, t_steps, p_steps)
            worst_diffs.append((cid, t_status, p_status, diff_desc))

        # Step-level matching (by system_id + resource_id + operation)
        t_keys = set()
        p_keys = set()
        for s in t_steps:
            k = (s['phase'], s['system_id'], s['resource_id'], s['operation'])
            t_keys.add(k)
        for s in p_steps:
            k = (s['phase'], s['system_id'], s['resource_id'], s['operation'])
            p_keys.add(k)

        step_total_expected += len(t_keys)
        step_total_predicted += len(p_keys)
        step_match += len(t_keys & p_keys)

        # Field-level accuracy on matched steps
        t_by_key = {}
        for s in t_steps:
            k = (s['phase'], s['system_id'], s['resource_id'], s['operation'])
            t_by_key[k] = s
        p_by_key = {}
        for s in p_steps:
            k = (s['phase'], s['system_id'], s['resource_id'], s['operation'])
            p_by_key[k] = s

        for k in t_keys & p_keys:
            ts = t_by_key[k]
            ps = p_by_key[k]
            for field in field_counts:
                field_counts[field] += 1
                if ts.get(field) == ps.get(field):
                    field_correct[field] += 1

    print(f"\n=== Sample Score ({total} cases) ===")
    print(f"Status accuracy: {status_correct}/{total} ({100*status_correct/total:.1f}%)")
    print(f"Step exact-match: {step_exact_match}/{total} ({100*step_exact_match/total:.1f}%)")

    if step_total_expected > 0:
        precision = step_match / step_total_predicted if step_total_predicted else 0
        recall = step_match / step_total_expected
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        print(f"Step P/R/F1: {precision:.3f}/{recall:.3f}/{f1:.3f}")

    for field in field_counts:
        if field_counts[field] > 0:
            acc = field_correct[field] / field_counts[field]
            print(f"  {field}: {field_correct[field]}/{field_counts[field]} ({100*acc:.1f}%)")

    # Print worst diffs (up to 5)
    worst_diffs.sort(key=lambda x: x[0])
    if worst_diffs:
        print(f"\n--- Diffs ({len(worst_diffs)} cases with differences) ---")
        for cid, t_st, p_st, diff in worst_diffs[:5]:
            print(f"\n{cid}: expected={t_st} got={p_st}")
            if diff:
                print(f"  {diff[:500]}")

    return status_correct, step_exact_match, total


def _compute_diff(cid, t_status, p_status, t_steps, p_steps):
    parts = []
    if t_status != p_status:
        parts.append(f"status: {t_status}->{p_status}")

    t_set = set()
    p_set = set()
    for s in t_steps:
        t_set.add((s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'], s.get('evidence_id', '')))
    for s in p_steps:
        p_set.add((s['phase'], s['system_id'], s['resource_id'], s['operation'], s['state'], s.get('evidence_id', '')))

    missing = t_set - p_set
    extra = p_set - t_set

    if missing:
        parts.append(f"missing({len(missing)}): " + '; '.join(
            f"{m[0]}/{m[1]}/{m[2]}/{m[3]}" for m in sorted(missing)[:3]))
    if extra:
        parts.append(f"extra({len(extra)}): " + '; '.join(
            f"{e[0]}/{e[1]}/{e[2]}/{e[3]}" for e in sorted(extra)[:3]))

    return ' | '.join(parts)


if __name__ == '__main__':
    path = sys.argv[1] if len(sys.argv) > 1 else None
    score(path)
