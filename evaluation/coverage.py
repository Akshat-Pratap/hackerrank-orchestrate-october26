import csv
import json
import os
import sys
from collections import defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUTPUT_CSV = os.path.join(REPO_ROOT, 'output.csv')
REQUESTS_CSV = os.path.join(REPO_ROOT, 'dataset', 'deletion_requests.csv')


def analyze_coverage(output_path=OUTPUT_CSV, requests_path=REQUESTS_CSV):
    if not os.path.exists(output_path):
        print(f"Error: {output_path} not found. Run code/main.py first.")
        sys.exit(1)

    reqs = {}
    with open(requests_path, encoding='utf-8') as f:
        for r in csv.DictReader(f):
            reqs[r['case_id']] = r

    outputs = {}
    with open(output_path, encoding='utf-8') as f:
        for r in csv.DictReader(f):
            outputs[r['case_id']] = r

    clusters = defaultdict(list)
    for cid, req in reqs.items():
        audit_at = req['audit_at']
        out = outputs.get(cid, {})
        clusters[audit_at].append((req, out))

    flagged = []
    print(f"{'Audit Cutoff':<22} {'N':>3} {'N/A':>4} {'CMP':>4} {'INC':>4} {'AcctOnly':>8} {'AvgSteps':>8}  Status")
    print("-" * 75)

    sorted_cutoffs = sorted(clusters.keys())
    for audit_at in sorted_cutoffs:
        items = clusters[audit_at]
        n = len(items)
        n_na = 0
        n_cmp = 0
        n_inc = 0
        n_acct_only = 0
        total_steps = 0

        for req, out in items:
            status = out.get('deletion_status', 'MISSING')
            steps = json.loads(out.get('steps_json', '[]'))
            total_steps += len(steps)

            if status == 'NOT_APPLICABLE':
                n_na += 1
            elif status == 'COMPLETE':
                n_cmp += 1
            elif status == 'INCOMPLETE':
                n_inc += 1

            if status != 'NOT_APPLICABLE':
                if steps and all(s.get('system_id') == 'account_service' for s in steps):
                    n_acct_only += 1

        avg_steps = total_steps / n if n > 0 else 0.0

        is_flagged = (avg_steps < 2.5 or n_acct_only >= 3) and n >= 5
        flag_str = "[FLAGGED]" if is_flagged else "OK"
        if is_flagged:
            flagged.append((audit_at, n, avg_steps, n_acct_only))

        print(f"{audit_at:<22} {n:>3} {n_na:>4} {n_cmp:>4} {n_inc:>4} {n_acct_only:>8} {avg_steps:>8.2f}  {flag_str}")

    print("-" * 75)
    print(f"Total clusters: {len(clusters)} | Flagged clusters: {len(flagged)}")
    return flagged


if __name__ == '__main__':
    analyze_coverage()
