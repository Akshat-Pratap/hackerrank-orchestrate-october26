#!/usr/bin/env python3
"""Ghost Data Still Exists — deletion audit pipeline.

Usage: python code/main.py
Writes output.csv to repository root.
"""
import csv
import json
import os
import re
import sys
from collections import defaultdict

REPO_ROOT = os.path.join(os.path.dirname(__file__), '..')
DATASET = os.path.join(REPO_ROOT, 'dataset')
CACHE_DIR = os.path.join(os.path.dirname(__file__), 'cache')
OUTPUT_PATH = os.path.join(REPO_ROOT, 'output.csv')

sys.path.insert(0, os.path.dirname(__file__))
from loaders import load_all_evidence, load_evidence_manifest
from identity import build_identity_index
from validate import validate_output


# ── Policy: required action per category ────────────────────────────────────
CATEGORY_ACTION = {
    'USER_PROFILE':         'DELETE',
    'SECONDARY_IDENTIFIER': 'DELETE',
    'SEARCH_INDEX_ENTRY':   'DELETE',
    'CACHE_ENTRY':          'DELETE',
    'USER_EXPORT':          'DELETE',
    'MARKETING_PROFILE':    'DELETE',
    'SUPPORT_ATTACHMENT':   'DELETE',
    'SUPPORT_MESSAGE':      'REDACT',
    'ANALYTICS_PROFILE':    'ANONYMIZE',
    'PRODUCT_TELEMETRY':    'ANONYMIZE',
    'EMAIL_DELIVERY_LOG':   'REDACT',
    'SECURITY_AUDIT_LOG':   'RETAIN',
    'LEGAL_HOLD_RECORD':    'RETAIN',
    'BACKUP_ARCHIVE':       'RETAIN_BLOCK',
    'ACCOUNT_TOMBSTONE':    'REDACT_TOMBSTONE',
    'DATA_FLOW':            'DISABLE',
}

# Phase ordering
PHASE_ORDER = {'FINDING': 0, 'REMEDIATION': 1, 'VERIFICATION': 2}
FINDING_OP_ORDER = {
    'REPORT_REMAINING_RECORD': 0, 'REPORT_EXPOSED_PII': 1,
    'REPORT_ACTIVE_DATA_FLOW': 2, 'REPORT_RESTORE_RISK': 3,
}
REMEDIATION_OP_ORDER = {
    'DISABLE_DATA_FLOW': 0, 'BLOCK_RESTORE': 1,
    'DELETE_RECORD': 2, 'REDACT_RECORD': 3, 'ANONYMIZE_RECORD': 4,
}
VERIFICATION_OP_ORDER = {
    'VERIFY_RECORD_ABSENT': 0, 'VERIFY_RECORD_PRESENT': 1,
    'VERIFY_RECORD_REDACTED': 2, 'VERIFY_RECORD_ANONYMIZED': 3,
    'VERIFY_DATA_FLOW_DISABLED': 4, 'VERIFY_RESTORE_BLOCKED': 5,
}


def load_csv(name):
    path = os.path.join(DATASET, name)
    with open(path, encoding='utf-8') as f:
        return list(csv.DictReader(f))


def main():
    # Load datasets
    deletion_requests = load_csv('deletion_requests.csv')
    user_identities = load_csv('user_identities.csv')
    user_audit_log = load_csv('user_audit_log.csv')
    system_activity = load_csv('system_activity.csv')
    deletion_rules = load_csv('deletion_rules.csv')
    evidence_manifest = load_evidence_manifest(
        os.path.join(DATASET, 'evidence_files.csv'))

    # Build indexes
    id_index = build_identity_index(user_identities, user_audit_log, system_activity)
    all_observations = load_all_evidence(evidence_manifest, DATASET, CACHE_DIR)

    # Flatten all observations into lookup structures
    obs_by_resource = defaultdict(list)   # resource_id -> [obs]
    obs_by_user = defaultdict(list)       # user_id -> [obs]
    obs_by_email = defaultdict(list)      # email -> [obs]

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

    # Build activity index: resource_id -> sorted events
    activity_by_resource = defaultdict(list)
    for act in system_activity:
        activity_by_resource[act['resource_id']].append(act)
    for k in activity_by_resource:
        activity_by_resource[k].sort(key=lambda a: a['event_time'])

    # Account-cluster assignment: resource_id -> user_id
    # (from activity DELETE_RECORD cluster [reported_at-80min, reported_at-40min])
    account_cluster_map = _build_account_cluster_map(deletion_requests, system_activity, id_index)

    # Process cases
    rows = []
    errors = 0
    for req in deletion_requests:
        try:
            status, steps = _decide(
                req, id_index, obs_by_resource, obs_by_user, obs_by_email,
                activity_by_resource, account_cluster_map)
            numbered = _number_steps(steps, status)
            rows.append({
                'case_id': req['case_id'],
                'deletion_status': status,
                'steps_json': json.dumps(numbered, separators=(',', ':')),
            })
        except Exception as e:
            errors += 1
            rows.append({
                'case_id': req['case_id'],
                'deletion_status': 'INCOMPLETE',
                'steps_json': '[]',
            })
            print('ERR %s: %s' % (req['case_id'], e), file=sys.stderr)

    # Sort by case_id
    rows.sort(key=lambda r: r['case_id'])

    # Write output
    out_path = os.path.abspath(OUTPUT_PATH)
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['case_id', 'deletion_status', 'steps_json'])
        w.writeheader()
        w.writerows(rows)

    print('Wrote %d rows to %s (%d errors)' % (len(rows), out_path, errors))
    validate_output(out_path)


# ── Case decision ────────────────────────────────────────────────────────────
def _decide(req, id_index, obs_by_resource, obs_by_user, obs_by_email,
            activity_by_resource, account_cluster_map):
    case_id = req['case_id']
    email = req['email'].strip().lower()
    audit_at = req['audit_at']
    reported_at = req.get('reported_at', audit_at)
    request_text = req.get('request_text', '')

    # 1. Identity resolution
    user_id = id_index.resolve_email(email)
    if user_id is None:
        return 'NOT_APPLICABLE', []

    identifiers = id_index.get_identifiers(user_id)
    all_emails = identifiers.get('emails', set()) | {email}
    all_phones = identifiers.get('phones', set())
    all_hashes = identifiers.get('email_hashes', set())
    account_id = identifiers.get('account_id', '')

    # 2. Check if non-deletion request
    if _is_non_deletion(request_text):
        return 'NOT_APPLICABLE', []

    # 3. Find all resources for this user
    user_resources = _find_user_resources(
        user_id, all_emails, all_phones, all_hashes, account_id,
        obs_by_resource, obs_by_user, obs_by_email,
        activity_by_resource, account_cluster_map, audit_at)

    if not user_resources:
        return 'INCOMPLETE', []

    # 4. Apply policy to each resource
    steps, is_complete = _apply_policy(user_resources, audit_at)

    status = 'COMPLETE' if is_complete else 'INCOMPLETE'
    return status, steps


def _is_non_deletion(request_text):
    """Return True if request_text is NOT a deletion request."""
    text = request_text.lower()
    # Positive deletion signals
    del_signals = ['delete', 'erase', 'forget me', 'remove my', 'close my account',
                   'right to erasure', 'right to be forgotten', 'droit', 'lösch',
                   'slett', 'elimina', 'borrar', 'excluir', 'удали', 'حذف',
                   'verwijder', 'wis mijn']
    if any(s in text for s in del_signals):
        return False
    # Non-deletion signals
    non_del = ['access', 'export', 'download', 'copy', 'correction', 'update',
               'opt out', 'unsubscribe', 'marketing', 'portability', 'transfer']
    if any(s in text for s in non_del):
        return True
    # Default: if no clear signal, treat as deletion
    return False


def _find_user_resources(user_id, all_emails, all_phones, all_hashes, account_id,
                          obs_by_resource, obs_by_user, obs_by_email,
                          activity_by_resource, account_cluster_map, audit_at):
    """Collect all resource observations for this user at or before audit_at."""
    # Key: (system_id, resource_id) -> best observation
    best_obs = {}

    def _add(ob):
        key = (ob['system_id'], ob['resource_id'])
        ob_time = ob.get('captured_at', '')
        # Accept observation if captured_at <= audit_at
        if ob_time > audit_at:
            # Try timeline reconstruction instead (handled in _apply_policy)
            # Still record it but mark as post-audit
            ob = dict(ob)
            ob['post_audit'] = True
        existing = best_obs.get(key)
        if existing is None:
            best_obs[key] = ob
        else:
            # Prefer most recent observation <= audit_at
            ob_at = ob.get('captured_at', '')
            ex_at = existing.get('captured_at', '')
            if not ob.get('post_audit') and (existing.get('post_audit') or ob_at > ex_at):
                best_obs[key] = ob

    # From user_id index
    for ob in obs_by_user.get(user_id, []):
        _add(ob)

    # From all emails (including historical)
    for em in all_emails:
        for ob in obs_by_email.get(em, []):
            _add(ob)

    # From phones
    for phone in all_phones:
        for ob in obs_by_email.get(phone, []):
            _add(ob)

    # From account cluster map
    for rid, uid in account_cluster_map.items():
        if uid == user_id and rid in obs_by_resource:
            for ob in obs_by_resource[rid]:
                _add(ob)

    # Check activity for resources targeted at account_id
    if account_id:
        for act in activity_by_resource.get(account_id, []):
            if act['event_time'] > audit_at:
                continue
            if act['event_type'] in ('DELETE_RECORD', 'SYNC_RECORD', 'RESTORE_BACKUP'):
                # account itself was touched; add synthetic observation
                if (account_id not in [o['resource_id'] for o in best_obs.values()]):
                    pass  # will be created by cluster map or evidence

    # Post-audit observations: reconstruct state from activity
    for key, ob in list(best_obs.items()):
        if ob.get('post_audit'):
            reconstructed = _reconstruct_from_activity(
                ob, activity_by_resource.get(ob['resource_id'], []), audit_at)
            best_obs[key] = reconstructed

    # For any resource found via activity with NO observation, synthesize from activity
    # Check account resources in activity targeted at this user
    for rid, acts in activity_by_resource.items():
        if rid.startswith('account_') or rid.startswith('tombstone_'):
            relevant = [a for a in acts if a['event_time'] <= audit_at]
            if not relevant:
                continue
            # Check if this resource is in any observation already
            if any(rid == r for _, r in best_obs.keys()):
                continue
            # Check if cluster map links it
            if account_cluster_map.get(rid) == user_id:
                # No evidence observation but activity shows it was targeted
                ob = _synthesize_from_activity(rid, relevant, audit_at)
                if ob:
                    _add(ob)

    return list(best_obs.values())


def _reconstruct_from_activity(ob, acts, audit_at):
    """Adjust observation state based on activity events <= audit_at."""
    ob = dict(ob)
    ob.pop('post_audit', None)
    valid_acts = [a for a in acts if a['event_time'] <= audit_at]
    if not valid_acts:
        return ob

    # Apply events in order
    state = ob.get('state', 'PRESENT')
    last_evidence = ob.get('file_id', '')
    for act in sorted(valid_acts, key=lambda a: a['event_time']):
        et = act['event_type']
        result = act['reported_result']
        if et == 'DELETE_RECORD' and result == 'SUCCESS':
            state = 'ABSENT'
        elif et in ('SYNC_RECORD', 'RESTORE_BACKUP'):
            state = 'PRESENT'
        elif et == 'ANONYMIZE_RECORD' and result == 'SUCCESS':
            state = 'ANONYMIZED'
        elif et == 'REDACT_RECORD' and result == 'SUCCESS':
            state = 'REDACTED'
        elif et == 'DISABLE_DATA_FLOW' and result == 'SUCCESS':
            state = 'DISABLED'
        elif et == 'BLOCK_RESTORE' and result == 'SUCCESS':
            state = 'BLOCKED'
        last_evidence = act['activity_id']

    ob['state'] = state
    if not ob.get('file_id') or ob.get('post_audit'):
        ob['file_id'] = last_evidence
    return ob


def _synthesize_from_activity(resource_id, acts, audit_at):
    """Create a synthetic observation from activity events alone."""
    from loaders import _cat, _system_from_resource_id
    sys_id = _system_from_resource_id(resource_id)
    cat = _cat(sys_id, resource_id)
    state = 'PRESENT'
    last_act = None
    for act in sorted(acts, key=lambda a: a['event_time']):
        if act['event_time'] > audit_at:
            break
        et = act['event_type']
        result = act.get('reported_result', '')
        if et == 'DELETE_RECORD' and result == 'SUCCESS':
            state = 'ABSENT'
        elif et in ('SYNC_RECORD', 'RESTORE_BACKUP'):
            state = 'PRESENT'
        last_act = act
    if last_act is None:
        return None
    return {
        'file_id': last_act['activity_id'],
        'system_id': sys_id,
        'resource_id': resource_id,
        'category': cat,
        'state': state,
        'captured_at': last_act['event_time'],
        'identifiers': {},
        'extra': {},
    }


# ── Policy application ───────────────────────────────────────────────────────
def _apply_policy(user_resources, audit_at):
    findings = []
    verif_complete = []
    is_complete = True

    for ob in user_resources:
        cat = ob.get('category', 'UNKNOWN')
        action = CATEGORY_ACTION.get(cat)
        if action is None:
            continue

        state = ob.get('state', 'PRESENT')
        sys_id = ob['system_id']
        rid = ob['resource_id']
        ev = ob.get('file_id', '')
        extra = ob.get('extra', {})

        # Post-audit evidence: no valid citation for COMPLETE
        # Only cite evidence with captured_at <= audit_at
        ob_time = ob.get('captured_at', '')
        ev_valid = bool(ev and ob_time <= audit_at and not ev.startswith('activity_'))

        if action == 'DELETE':
            if state == 'ABSENT':
                if ev_valid:
                    verif_complete.append(_step('VERIFICATION', sys_id, rid,
                        'VERIFY_RECORD_ABSENT', 'ABSENT', ev))
                # else: record was deleted but no valid evidence — skip for COMPLETE
                # but it shouldn't cause INCOMPLETE
            else:
                is_complete = False
                findings.append(_step('FINDING', sys_id, rid,
                    'REPORT_REMAINING_RECORD', 'PRESENT', ev if ev_valid else ev))

        elif action == 'REDACT':
            if state in ('REDACTED', 'ABSENT'):
                op = 'VERIFY_RECORD_REDACTED' if state == 'REDACTED' else 'VERIFY_RECORD_ABSENT'
                st = state
                if ev_valid:
                    verif_complete.append(_step('VERIFICATION', sys_id, rid, op, st, ev))
            else:
                is_complete = False
                findings.append(_step('FINDING', sys_id, rid,
                    'REPORT_EXPOSED_PII', 'PRESENT', ev if ev_valid else ev))

        elif action == 'ANONYMIZE':
            if state in ('ANONYMIZED', 'ABSENT'):
                op = 'VERIFY_RECORD_ANONYMIZED' if state == 'ANONYMIZED' else 'VERIFY_RECORD_ABSENT'
                if ev_valid:
                    verif_complete.append(_step('VERIFICATION', sys_id, rid, op, state, ev))
            else:
                is_complete = False
                findings.append(_step('FINDING', sys_id, rid,
                    'REPORT_EXPOSED_PII', 'PRESENT', ev if ev_valid else ev))

        elif action == 'RETAIN':
            if state == 'PRESENT' and ev_valid:
                verif_complete.append(_step('VERIFICATION', sys_id, rid,
                    'VERIFY_RECORD_PRESENT', 'PRESENT', ev))

        elif action == 'RETAIN_BLOCK':
            if state == 'BLOCKED':
                if ev_valid:
                    verif_complete.append(_step('VERIFICATION', sys_id, rid,
                        'VERIFY_RESTORE_BLOCKED', 'BLOCKED', ev))
            else:
                is_complete = False
                findings.append(_step('FINDING', sys_id, rid,
                    'REPORT_RESTORE_RISK', 'ACTIVE', ev if ev_valid else ev))

        elif action == 'DISABLE':
            if state == 'DISABLED':
                if ev_valid:
                    verif_complete.append(_step('VERIFICATION', sys_id, rid,
                        'VERIFY_DATA_FLOW_DISABLED', 'DISABLED', ev))
            else:
                is_complete = False
                findings.append(_step('FINDING', sys_id, rid,
                    'REPORT_ACTIVE_DATA_FLOW', 'ACTIVE', ev if ev_valid else ev))

        elif action == 'REDACT_TOMBSTONE':
            has_pii = extra.get('tombstone_has_pii', True)
            if has_pii:
                is_complete = False
                findings.append(_step('FINDING', sys_id, rid,
                    'REPORT_EXPOSED_PII', 'PRESENT', ev if ev_valid else ev))
            else:
                if ev_valid:
                    verif_complete.append(_step('VERIFICATION', sys_id, rid,
                        'VERIFY_RECORD_REDACTED', 'REDACTED', ev))

    if is_complete:
        return verif_complete, True

    # INCOMPLETE: generate full plan
    steps = list(findings)

    # Remediation (ordered: disable → block → delete/redact/anonymize)
    for f in findings:
        op = f['operation']
        sys_id = f['system_id']
        rid = f['resource_id']
        if op == 'REPORT_ACTIVE_DATA_FLOW':
            steps.append(_step('REMEDIATION', sys_id, rid, 'DISABLE_DATA_FLOW', 'DISABLED', ''))
        elif op == 'REPORT_RESTORE_RISK':
            steps.append(_step('REMEDIATION', sys_id, rid, 'BLOCK_RESTORE', 'BLOCKED', ''))

    for f in findings:
        op = f['operation']
        sys_id = f['system_id']
        rid = f['resource_id']
        if op == 'REPORT_REMAINING_RECORD':
            steps.append(_step('REMEDIATION', sys_id, rid, 'DELETE_RECORD', 'ABSENT', ''))
        elif op == 'REPORT_EXPOSED_PII':
            # Determine REDACT vs ANONYMIZE
            cat = _infer_cat(sys_id, rid)
            action = CATEGORY_ACTION.get(cat, 'REDACT')
            if action == 'ANONYMIZE':
                steps.append(_step('REMEDIATION', sys_id, rid, 'ANONYMIZE_RECORD', 'ANONYMIZED', ''))
            else:
                steps.append(_step('REMEDIATION', sys_id, rid, 'REDACT_RECORD', 'REDACTED', ''))

    # Verification for findings
    for f in findings:
        op = f['operation']
        sys_id = f['system_id']
        rid = f['resource_id']
        if op in ('REPORT_REMAINING_RECORD',):
            steps.append(_step('VERIFICATION', sys_id, rid, 'VERIFY_RECORD_ABSENT', 'ABSENT', ''))
        elif op == 'REPORT_EXPOSED_PII':
            cat = _infer_cat(sys_id, rid)
            action = CATEGORY_ACTION.get(cat, 'REDACT')
            if action == 'ANONYMIZE':
                steps.append(_step('VERIFICATION', sys_id, rid, 'VERIFY_RECORD_ANONYMIZED', 'ANONYMIZED', ''))
            else:
                steps.append(_step('VERIFICATION', sys_id, rid, 'VERIFY_RECORD_REDACTED', 'REDACTED', ''))
        elif op == 'REPORT_ACTIVE_DATA_FLOW':
            steps.append(_step('VERIFICATION', sys_id, rid, 'VERIFY_DATA_FLOW_DISABLED', 'DISABLED', ''))
        elif op == 'REPORT_RESTORE_RISK':
            steps.append(_step('VERIFICATION', sys_id, rid, 'VERIFY_RESTORE_BLOCKED', 'BLOCKED', ''))

    # Verification for already-complete resources (no evidence_id in INCOMPLETE)
    for vc in verif_complete:
        vc_copy = dict(vc)
        vc_copy['evidence_id'] = ''
        steps.append(vc_copy)

    return steps, False


def _step(phase, sys_id, rid, op, state, ev):
    return {
        'phase': phase, 'system_id': sys_id, 'resource_id': rid,
        'operation': op, 'state': state, 'evidence_id': ev,
    }


def _infer_cat(sys_id, rid):
    from loaders import _cat
    return _cat(sys_id, rid)


# ── Step numbering ───────────────────────────────────────────────────────────
def _step_key(s):
    phase = PHASE_ORDER.get(s['phase'], 99)
    op_maps = {
        'FINDING': FINDING_OP_ORDER,
        'REMEDIATION': REMEDIATION_OP_ORDER,
        'VERIFICATION': VERIFICATION_OP_ORDER,
    }
    op_idx = op_maps.get(s['phase'], {}).get(s['operation'], 99)
    return (phase, op_idx, s['system_id'], s['resource_id'])


def _number_steps(steps, status):
    if status == 'NOT_APPLICABLE':
        return []

    # Deduplicate
    seen = set()
    unique = []
    for s in steps:
        key = (s['phase'], s['system_id'], s['resource_id'], s['operation'])
        if key not in seen:
            seen.add(key)
            unique.append(s)

    unique.sort(key=_step_key)

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


# ── Account cluster assignment ───────────────────────────────────────────────
def _build_account_cluster_map(deletion_requests, system_activity, id_index):
    """Map account resource_id -> user_id using DELETE_RECORD cluster window.

    Rule: candidate accounts = DELETE_RECORD on account_service within
    [reported_at - 80 min, reported_at - 40 min]. Assign one-to-one deterministically.
    """
    import datetime

    def _parse_dt(s):
        s = s.strip().replace('Z', '+00:00')
        try:
            return datetime.datetime.fromisoformat(s)
        except Exception:
            return None

    # Build account DELETE_RECORD events indexed by time
    account_deletes = {}  # resource_id -> event_time (datetime)
    for act in system_activity:
        if act['event_type'] == 'DELETE_RECORD' and act['target_system'] == 'account_service':
            t = _parse_dt(act['event_time'])
            if t:
                account_deletes[act['resource_id']] = t

    # For each case, find cluster window candidates
    claimed = {}  # account_rid -> user_id (first claimer wins)
    # Sort requests by (reported_at, case_id) for determinism
    sorted_reqs = sorted(deletion_requests, key=lambda r: (r.get('reported_at', ''), r['case_id']))

    for req in sorted_reqs:
        email = req['email'].strip().lower()
        user_id = id_index.resolve_email(email)
        if user_id is None:
            continue

        reported_at = _parse_dt(req.get('reported_at', ''))
        if not reported_at:
            continue

        lo = reported_at - datetime.timedelta(minutes=80)
        hi = reported_at - datetime.timedelta(minutes=40)

        candidates = [rid for rid, t in account_deletes.items()
                      if lo <= t <= hi and rid not in claimed]

        if len(candidates) == 1:
            claimed[candidates[0]] = user_id
        elif len(candidates) > 1:
            # Pick by stable sort (earliest event, then resource_id)
            candidates.sort(key=lambda r: (account_deletes[r], r))
            claimed[candidates[0]] = user_id

    return claimed


if __name__ == '__main__':
    main()
