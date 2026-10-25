"""Plan builder: sort and number steps according to the ordering contract."""

# Phase ordering
PHASE_ORDER = {'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}

# Operation ordering within each phase (index = sort key)
FINDING_OP_ORDER = {
    'REPORT_REMAINING_RECORD': 0,
    'REPORT_EXPOSED_PII': 1,
    'REPORT_ACTIVE_DATA_FLOW': 2,
    'REPORT_RESTORE_RISK': 3,
}
REMEDIATION_OP_ORDER = {
    'DISABLE_DATA_FLOW': 0,
    'BLOCK_RESTORE': 1,
    'DELETE_RECORD': 2,
    'REDACT_RECORD': 3,
    'ANONYMIZE_RECORD': 4,
}
VERIFICATION_OP_ORDER = {
    'VERIFY_RECORD_ABSENT': 0,
    'VERIFY_RECORD_PRESENT': 1,
    'VERIFY_RECORD_REDACTED': 2,
    'VERIFY_RECORD_ANONYMIZED': 3,
    'VERIFY_DATA_FLOW_DISABLED': 4,
    'VERIFY_RESTORE_BLOCKED': 5,
}

OP_ORDERS = {
    'FINDING': FINDING_OP_ORDER,
    'REMEDIATION': REMEDIATION_OP_ORDER,
    'VERIFICATION': VERIFICATION_OP_ORDER,
}


def _step_sort_key(step):
    phase = step.get('phase', '')
    op = step.get('operation', '')
    sys = step.get('system_id', '')
    res = step.get('resource_id', '')

    phase_idx = PHASE_ORDER.get(phase, 99)
    op_idx = OP_ORDERS.get(phase, {}).get(op, 99)

    return (phase_idx, op_idx, sys, res)


def build_steps(raw_steps, status):
    """Sort steps by contract ordering and assign consecutive step_no.

    Returns list of step dicts with step_no, phase, system_id, resource_id,
    operation, state, evidence_id.
    """
    if status == 'NOT_APPLICABLE':
        return []

    # Deduplicate steps (same phase + system_id + resource_id + operation)
    seen = set()
    unique = []
    for s in raw_steps:
        key = (s['phase'], s['system_id'], s['resource_id'], s['operation'])
        if key not in seen:
            seen.add(key)
            unique.append(s)

    # Sort
    unique.sort(key=_step_sort_key)

    # Number
    result = []
    for i, s in enumerate(unique, 1):
        result.append({
            'step_no': i,
            'phase': s['phase'],
            'system_id': s['system_id'],
            'resource_id': s['resource_id'],
            'operation': s['operation'],
            'state': s['state'],
            'evidence_id': s.get('evidence_id', ''),
        })

    return result
