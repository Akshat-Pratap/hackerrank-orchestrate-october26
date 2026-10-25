"""Output validator: checks output.csv against the contract."""
import csv
import json
import sys


ALLOWED_STATUS = {'COMPLETE', 'INCOMPLETE', 'NOT_APPLICABLE'}
ALLOWED_PHASES = {'FINDING', 'REMEDIATION', 'VERIFICATION'}
ALLOWED_OPS = {
    ('FINDING', 'REPORT_REMAINING_RECORD', 'PRESENT'),
    ('FINDING', 'REPORT_EXPOSED_PII', 'PRESENT'),
    ('FINDING', 'REPORT_ACTIVE_DATA_FLOW', 'ACTIVE'),
    ('FINDING', 'REPORT_RESTORE_RISK', 'ACTIVE'),
    ('REMEDIATION', 'DISABLE_DATA_FLOW', 'DISABLED'),
    ('REMEDIATION', 'BLOCK_RESTORE', 'BLOCKED'),
    ('REMEDIATION', 'DELETE_RECORD', 'ABSENT'),
    ('REMEDIATION', 'REDACT_RECORD', 'REDACTED'),
    ('REMEDIATION', 'ANONYMIZE_RECORD', 'ANONYMIZED'),
    ('VERIFICATION', 'VERIFY_RECORD_ABSENT', 'ABSENT'),
    ('VERIFICATION', 'VERIFY_RECORD_PRESENT', 'PRESENT'),
    ('VERIFICATION', 'VERIFY_RECORD_REDACTED', 'REDACTED'),
    ('VERIFICATION', 'VERIFY_RECORD_ANONYMIZED', 'ANONYMIZED'),
    ('VERIFICATION', 'VERIFY_DATA_FLOW_DISABLED', 'DISABLED'),
    ('VERIFICATION', 'VERIFY_RESTORE_BLOCKED', 'BLOCKED'),
}


def validate_output(output_path, evidence_csv_path=None):
    """Validate output.csv format. Print errors to stderr. Return True if valid."""
    errors = []

    with open(output_path, encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Check header
    expected_cols = ['case_id', 'deletion_status', 'steps_json']
    if reader.fieldnames != expected_cols:
        errors.append(f"Header mismatch: got {reader.fieldnames}, expected {expected_cols}")

    # Check row count
    if len(rows) != 518:
        errors.append(f"Row count: {len(rows)}, expected 518")

    # Check sorted
    case_ids = [r['case_id'] for r in rows]
    if case_ids != sorted(case_ids):
        errors.append("Rows not sorted by case_id")

    # Check each row
    for r in rows:
        cid = r['case_id']

        if r['deletion_status'] not in ALLOWED_STATUS:
            errors.append(f"{cid}: invalid status '{r['deletion_status']}'")

        try:
            steps = json.loads(r['steps_json'])
        except json.JSONDecodeError as e:
            errors.append(f"{cid}: invalid JSON: {e}")
            continue

        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json not a list")
            continue

        if r['deletion_status'] == 'NOT_APPLICABLE':
            if steps:
                errors.append(f"{cid}: NOT_APPLICABLE must have empty steps")
            continue

        # Check step_no consecutive
        for i, s in enumerate(steps, 1):
            if s.get('step_no') != i:
                errors.append(f"{cid}: step_no {s.get('step_no')} expected {i}")
                break

        # Check allowed combos
        for s in steps:
            combo = (s.get('phase'), s.get('operation'), s.get('state'))
            if combo not in ALLOWED_OPS:
                errors.append(f"{cid}: invalid combo {combo}")

        # Check phase ordering
        phase_indices = [{'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}.get(s.get('phase'), -1) for s in steps]
        if phase_indices != sorted(phase_indices):
            errors.append(f"{cid}: phases not in order")

        # Check COMPLETE cases have only VERIFICATION and non-empty steps
        if r['deletion_status'] == 'COMPLETE':
            if not steps:
                errors.append(f"{cid}: COMPLETE case has empty steps")
                continue
            for s in steps:
                if s.get('phase') != 'VERIFICATION':
                    errors.append(f"{cid}: COMPLETE case has non-VERIFICATION step")
                    break
                if not s.get('evidence_id'):
                    errors.append(f"{cid}: COMPLETE verification missing evidence_id")
                    break

        # Check INCOMPLETE: remediation/verification evidence_id should be empty
        if r['deletion_status'] == 'INCOMPLETE':
            for s in steps:
                if s.get('phase') in ('REMEDIATION', 'VERIFICATION') and s.get('evidence_id'):
                    errors.append(f"{cid}: INCOMPLETE remediation/verification has evidence_id")
                    break

    if errors:
        print(f"VALIDATION FAILED: {len(errors)} errors", file=sys.stderr)
        for e in errors[:20]:
            print(f"  {e}", file=sys.stderr)
        return False
    else:
        print("VALIDATION PASSED", file=sys.stderr)
        return True
