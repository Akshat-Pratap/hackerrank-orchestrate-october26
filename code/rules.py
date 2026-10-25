"""Rules engine: decide deletion status and generate raw steps for each case."""
import re
from collections import defaultdict


# Operation ordering within phases (as specified in task contract)
FINDING_OPS = [
    'REPORT_REMAINING_RECORD',
    'REPORT_EXPOSED_PII',
    'REPORT_ACTIVE_DATA_FLOW',
    'REPORT_RESTORE_RISK',
]
REMEDIATION_OPS = [
    'DISABLE_DATA_FLOW',
    'BLOCK_RESTORE',
    'DELETE_RECORD',
    'REDACT_RECORD',
    'ANONYMIZE_RECORD',
]
VERIFICATION_OPS = [
    'VERIFY_RECORD_ABSENT',
    'VERIFY_RECORD_PRESENT',
    'VERIFY_RECORD_REDACTED',
    'VERIFY_RECORD_ANONYMIZED',
    'VERIFY_DATA_FLOW_DISABLED',
    'VERIFY_RESTORE_BLOCKED',
]

# Category -> required action mapping
CATEGORY_ACTION = {
    'USER_PROFILE': 'DELETE',
    'SECONDARY_IDENTIFIER': 'DELETE',
    'SEARCH_INDEX_ENTRY': 'DELETE',
    'CACHE_ENTRY': 'DELETE',
    'USER_EXPORT': 'DELETE',
    'MARKETING_PROFILE': 'DELETE',
    'SUPPORT_MESSAGE': 'REDACT',
    'SUPPORT_ATTACHMENT': 'DELETE',
    'ANALYTICS_PROFILE': 'ANONYMIZE',
    'PRODUCT_TELEMETRY': 'ANONYMIZE',
    'EMAIL_DELIVERY_LOG': 'REDACT',
    'SECURITY_AUDIT_LOG': 'RETAIN',
    'LEGAL_HOLD_RECORD': 'RETAIN',
    'BACKUP_ARCHIVE': 'RETAIN_BLOCK',
    'ACCOUNT_TOMBSTONE': 'REDACT_TOMBSTONE',
    'DATA_FLOW': 'DISABLE',
}


def decide_case(req, id_index, all_observations, timeline, deletion_rules, evidence_manifest):
    """Decide deletion status and generate raw step list for a case.

    Returns: (status, steps) where steps is list of raw step dicts (unsorted, unnumbered).
    """
    case_id = req['case_id']
    email = req['email']
    audit_at = req['audit_at']
    request_text = req.get('request_text', '')

    # Step 1: Resolve identity
    user_id = id_index.resolve_email(email)
    if user_id is None:
        return 'NOT_APPLICABLE', []

    identifiers = id_index.get_identifiers(user_id)
    account_id = identifiers.get('account_id', '')

    # Step 2: Check if this is NOT_APPLICABLE (non-deletion request)
    if _is_non_deletion(account_id, timeline, request_text):
        return 'NOT_APPLICABLE', []

    # Step 3: Find all resources belonging to this user from evidence
    user_resources = _find_user_resources(user_id, identifiers, all_observations,
                                          timeline, evidence_manifest, audit_at)

    # Step 4: Determine state of each resource at audit_at
    resource_states = _determine_resource_states(user_resources, audit_at, timeline,
                                                  all_observations, evidence_manifest)

    # Step 5: Apply deletion rules and determine what needs to happen
    steps, is_complete = _apply_rules_and_generate_steps(resource_states, audit_at,
                                                          evidence_manifest)

    status = 'COMPLETE' if is_complete else 'INCOMPLETE'
    return status, steps


def _is_non_deletion(account_id, timeline, request_text):
    """Check if request is classified as non-deletion."""
    if account_id in timeline.classify_request_accounts:
        return True
    return False


def _find_user_resources(user_id, identifiers, all_observations, timeline,
                          evidence_manifest, audit_at):
    """Find all resources belonging to a user across all evidence files.

    Returns dict: (system_id, resource_id) -> list of observations
    """
    resources = defaultdict(list)
    emails = identifiers.get('emails', set())
    phones = identifiers.get('phones', set())
    email_hashes = identifiers.get('email_hashes', set())

    for file_id, obs_list in all_observations.items():
        for ob in obs_list:
            if _observation_matches_user(ob, user_id, emails, phones, email_hashes):
                key = (ob['system_id'], ob['resource_id'])
                resources[key].append(ob)

    # Also check timeline resource_identity_links
    for resource_id, link_info in timeline.resource_identity_links.items():
        if link_info.get('user_id') == user_id:
            # Find observations for this resource
            for file_id, obs_list in all_observations.items():
                for ob in obs_list:
                    if ob['resource_id'] == resource_id:
                        key = (ob['system_id'], ob['resource_id'])
                        if ob not in resources[key]:
                            resources[key].append(ob)

    # Also check activity events for resources linked to this user
    for event in timeline.get_all_events():
        rid = event['resource_id']
        if rid.startswith('account_'):
            # Check if this account matches
            num = rid.replace('account_', '')
            if user_id == f'user_{num}':
                # Find observations for this resource
                for file_id, obs_list in all_observations.items():
                    for ob in obs_list:
                        if ob['resource_id'] == rid:
                            key = (ob['system_id'], ob['resource_id'])
                            if ob not in resources[key]:
                                resources[key].append(ob)

    return resources


def _observation_matches_user(ob, user_id, emails, phones, email_hashes):
    """Check if an observation's identifiers match the user."""
    ids = ob.get('identifiers', {})

    uid = ids.get('user_id', '')
    if uid == user_id:
        return True

    email = ids.get('email', '')
    if email and email in emails:
        return True

    phone = ids.get('phone', '')
    if phone and phone in phones:
        return True

    ehash = ids.get('email_hash', '')
    if ehash and ehash in email_hashes:
        return True

    return False


def _determine_resource_states(user_resources, audit_at, timeline,
                                all_observations, evidence_manifest):
    """Determine the state of each resource at audit_at.

    Returns list of ResourceState dicts:
      system_id, resource_id, category, state, evidence_id, evidence_captured_at
    """
    states = []

    for (system_id, resource_id), obs_list in user_resources.items():
        if not obs_list:
            continue

        # Filter observations: prefer latest observation captured_at <= audit_at
        # If no observation <= audit_at, we may still use later evidence to identify
        # resources but must reconstruct state from activity timeline
        valid_obs = [o for o in obs_list if o['captured_at'] <= audit_at]

        if valid_obs:
            # Use the latest valid observation
            best = max(valid_obs, key=lambda o: o['captured_at'])
        else:
            # Evidence captured after audit_at: reconstruct state from timeline
            best = _reconstruct_state_from_timeline(system_id, resource_id,
                                                      obs_list, audit_at, timeline)
            if best is None:
                # Use the observation but note it's post-audit
                best = obs_list[0]
                # Must reconstruct state from activity timeline
                best = _apply_timeline_reconstruction(best, audit_at, timeline)

        states.append({
            'system_id': system_id,
            'resource_id': resource_id,
            'category': best.get('category', 'UNKNOWN'),
            'state': best.get('state', 'PRESENT'),
            'evidence_id': best.get('file_id', ''),
            'evidence_captured_at': best.get('captured_at', ''),
            'tombstone_has_pii': best.get('tombstone_has_pii', False),
            'retention_until': best.get('retention_until', ''),
            'connector_name': best.get('connector_name', ''),
            'archive_key': best.get('archive_key', ''),
            'replica_type': best.get('replica_type'),
        })

    return states


def _reconstruct_state_from_timeline(system_id, resource_id, obs_list, audit_at, timeline):
    """Reconstruct resource state at audit_at from activity timeline."""
    events = timeline.get_events_before(resource_id, audit_at)

    if not events:
        return None

    # Find the last relevant event
    last_event = events[-1]

    # Start with the last observation for metadata
    ob = obs_list[0].copy()
    ob['captured_at'] = last_event['event_time']

    # Determine state from event type
    et = last_event['event_type']
    result = last_event['reported_result']

    if et == 'DELETE_RECORD':
        if result == 'SUCCESS':
            ob['state'] = 'ABSENT'
        else:
            ob['state'] = 'PRESENT'
    elif et == 'SYNC_RECORD':
        # Sync means data was copied/recreated
        ob['state'] = 'PRESENT'
    elif et == 'ANONYMIZE_RECORD':
        if result == 'SUCCESS':
            ob['state'] = 'ANONYMIZED'
        else:
            ob['state'] = 'IDENTIFIABLE'
    elif et == 'REDACT_RECORD':
        if result == 'SUCCESS':
            ob['state'] = 'REDACTED'
        else:
            ob['state'] = 'IDENTIFIABLE'
    elif et == 'DISABLE_DATA_FLOW':
        if result == 'SUCCESS':
            ob['state'] = 'DISABLED'
        else:
            ob['state'] = 'ACTIVE'
    elif et == 'BLOCK_RESTORE':
        if result == 'SUCCESS':
            ob['state'] = 'BLOCKED'
        else:
            ob['state'] = 'ACTIVE'
    elif et == 'RESTORE_BACKUP':
        ob['state'] = 'PRESENT'
    elif et == 'CHECK_DATA_FLOW':
        # Not a state change, check the last state-changing event
        pass
    elif et == 'CHECK_RESTORE_ACCESS':
        pass

    # Check for post-delete SYNC_RECORD that recreates data
    _check_recreation(ob, resource_id, events)

    # Use activity_id as evidence_id for timeline-reconstructed states
    ob['file_id'] = last_event['activity_id']

    return ob


def _check_recreation(ob, resource_id, events):
    """Check if a deleted record was recreated by sync/restore after deletion."""
    last_delete = None
    last_sync_after_delete = None

    for e in events:
        if e['event_type'] == 'DELETE_RECORD' and e['reported_result'] == 'SUCCESS':
            last_delete = e
            last_sync_after_delete = None
        elif e['event_type'] in ('SYNC_RECORD', 'RESTORE_BACKUP') and last_delete:
            last_sync_after_delete = e

    if last_sync_after_delete:
        ob['state'] = 'PRESENT'


def _apply_timeline_reconstruction(ob, audit_at, timeline):
    """Apply timeline events to adjust a post-audit observation."""
    ob = ob.copy()
    events = timeline.get_events_before(ob['resource_id'], audit_at)

    if events:
        last_event = events[-1]
        et = last_event['event_type']
        result = last_event['reported_result']

        if et == 'DELETE_RECORD' and result == 'SUCCESS':
            ob['state'] = 'ABSENT'
        elif et == 'SYNC_RECORD':
            ob['state'] = 'PRESENT'
        elif et == 'ANONYMIZE_RECORD' and result == 'SUCCESS':
            ob['state'] = 'ANONYMIZED'
        elif et == 'REDACT_RECORD' and result == 'SUCCESS':
            ob['state'] = 'REDACTED'
        elif et == 'DISABLE_DATA_FLOW' and result == 'SUCCESS':
            ob['state'] = 'DISABLED'
        elif et == 'BLOCK_RESTORE' and result == 'SUCCESS':
            ob['state'] = 'BLOCKED'

        _check_recreation(ob, ob['resource_id'], events)
        ob['file_id'] = last_event['activity_id']

    return ob


def _apply_rules_and_generate_steps(resource_states, audit_at, evidence_manifest):
    """Apply deletion rules and generate steps.

    Returns (steps, is_complete).
    steps is list of raw step dicts before ordering/numbering.
    """
    findings = []
    verifications_complete = []
    is_complete = True

    for rs in resource_states:
        category = rs['category']
        state = rs['state']
        system_id = rs['system_id']
        resource_id = rs['resource_id']
        evidence_id = rs['evidence_id']

        required_action = CATEGORY_ACTION.get(category)
        if required_action is None:
            continue

        if required_action == 'DELETE':
            if state == 'ABSENT':
                verifications_complete.append({
                    'phase': 'VERIFICATION',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': evidence_id,
                })
            else:
                is_complete = False
                findings.append({
                    'phase': 'FINDING',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'REPORT_REMAINING_RECORD',
                    'state': 'PRESENT',
                    'evidence_id': evidence_id,
                })

        elif required_action == 'REDACT':
            if state == 'REDACTED':
                verifications_complete.append({
                    'phase': 'VERIFICATION',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'VERIFY_RECORD_REDACTED',
                    'state': 'REDACTED',
                    'evidence_id': evidence_id,
                })
            elif state == 'ABSENT':
                verifications_complete.append({
                    'phase': 'VERIFICATION',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': evidence_id,
                })
            else:
                is_complete = False
                findings.append({
                    'phase': 'FINDING',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'REPORT_EXPOSED_PII',
                    'state': 'PRESENT',
                    'evidence_id': evidence_id,
                })

        elif required_action == 'ANONYMIZE':
            if state == 'ANONYMIZED':
                verifications_complete.append({
                    'phase': 'VERIFICATION',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'VERIFY_RECORD_ANONYMIZED',
                    'state': 'ANONYMIZED',
                    'evidence_id': evidence_id,
                })
            elif state == 'ABSENT':
                verifications_complete.append({
                    'phase': 'VERIFICATION',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'VERIFY_RECORD_ABSENT',
                    'state': 'ABSENT',
                    'evidence_id': evidence_id,
                })
            else:
                is_complete = False
                findings.append({
                    'phase': 'FINDING',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'REPORT_EXPOSED_PII',
                    'state': 'PRESENT',
                    'evidence_id': evidence_id,
                })

        elif required_action == 'RETAIN':
            # Security audit logs, legal holds: must be retained
            verifications_complete.append({
                'phase': 'VERIFICATION',
                'system_id': system_id,
                'resource_id': resource_id,
                'operation': 'VERIFY_RECORD_PRESENT',
                'state': 'PRESENT',
                'evidence_id': evidence_id,
            })

        elif required_action == 'RETAIN_BLOCK':
            # Backup archives: retain but block restore
            if state == 'BLOCKED':
                verifications_complete.append({
                    'phase': 'VERIFICATION',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'VERIFY_RESTORE_BLOCKED',
                    'state': 'BLOCKED',
                    'evidence_id': evidence_id,
                })
            else:
                is_complete = False
                findings.append({
                    'phase': 'FINDING',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'REPORT_RESTORE_RISK',
                    'state': 'ACTIVE',
                    'evidence_id': evidence_id,
                })

        elif required_action == 'DISABLE':
            # Data flows: must be disabled
            if state == 'DISABLED':
                verifications_complete.append({
                    'phase': 'VERIFICATION',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'VERIFY_DATA_FLOW_DISABLED',
                    'state': 'DISABLED',
                    'evidence_id': evidence_id,
                })
            else:
                is_complete = False
                findings.append({
                    'phase': 'FINDING',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'REPORT_ACTIVE_DATA_FLOW',
                    'state': 'ACTIVE',
                    'evidence_id': evidence_id,
                })

        elif required_action == 'REDACT_TOMBSTONE':
            # Account tombstone: keep user_id but remove PII
            if rs.get('tombstone_has_pii'):
                is_complete = False
                findings.append({
                    'phase': 'FINDING',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'REPORT_EXPOSED_PII',
                    'state': 'PRESENT',
                    'evidence_id': evidence_id,
                })
            else:
                verifications_complete.append({
                    'phase': 'VERIFICATION',
                    'system_id': system_id,
                    'resource_id': resource_id,
                    'operation': 'VERIFY_RECORD_REDACTED',
                    'state': 'REDACTED',
                    'evidence_id': evidence_id,
                })

    if is_complete:
        return verifications_complete, True
    else:
        # Generate full plan: findings + remediation + verification
        steps = []
        steps.extend(findings)

        # Generate remediation steps for each finding
        remediations = []
        for f in findings:
            rem = _generate_remediation(f)
            if rem:
                remediations.extend(rem)
        steps.extend(remediations)

        # Generate verification steps for everything
        # Include verification for already-complete resources too
        all_verifications = []
        for f in findings:
            ver = _generate_verification_for_finding(f)
            all_verifications.extend(ver)

        # Add verification for already-complete resources (already deleted, retained, etc.)
        for vc in verifications_complete:
            vc_copy = vc.copy()
            vc_copy['evidence_id'] = ''  # In INCOMPLETE, verification is future
            all_verifications.append(vc_copy)

        steps.extend(all_verifications)
        return steps, False


def _generate_remediation(finding):
    """Generate remediation step(s) for a finding."""
    op = finding['operation']
    system_id = finding['system_id']
    resource_id = finding['resource_id']

    if op == 'REPORT_REMAINING_RECORD':
        return [{
            'phase': 'REMEDIATION',
            'system_id': system_id,
            'resource_id': resource_id,
            'operation': 'DELETE_RECORD',
            'state': 'ABSENT',
            'evidence_id': '',
        }]
    elif op == 'REPORT_EXPOSED_PII':
        # Determine if REDACT or ANONYMIZE based on category
        # Need to look at the finding's context
        category = _infer_category_from_system_resource(system_id, resource_id)
        action = CATEGORY_ACTION.get(category, 'REDACT')
        if action in ('ANONYMIZE',):
            return [{
                'phase': 'REMEDIATION',
                'system_id': system_id,
                'resource_id': resource_id,
                'operation': 'ANONYMIZE_RECORD',
                'state': 'ANONYMIZED',
                'evidence_id': '',
            }]
        else:
            return [{
                'phase': 'REMEDIATION',
                'system_id': system_id,
                'resource_id': resource_id,
                'operation': 'REDACT_RECORD',
                'state': 'REDACTED',
                'evidence_id': '',
            }]
    elif op == 'REPORT_ACTIVE_DATA_FLOW':
        return [{
            'phase': 'REMEDIATION',
            'system_id': system_id,
            'resource_id': resource_id,
            'operation': 'DISABLE_DATA_FLOW',
            'state': 'DISABLED',
            'evidence_id': '',
        }]
    elif op == 'REPORT_RESTORE_RISK':
        return [{
            'phase': 'REMEDIATION',
            'system_id': system_id,
            'resource_id': resource_id,
            'operation': 'BLOCK_RESTORE',
            'state': 'BLOCKED',
            'evidence_id': '',
        }]
    return []


def _generate_verification_for_finding(finding):
    """Generate verification step for a remediated finding."""
    op = finding['operation']
    system_id = finding['system_id']
    resource_id = finding['resource_id']

    if op == 'REPORT_REMAINING_RECORD':
        return [{
            'phase': 'VERIFICATION',
            'system_id': system_id,
            'resource_id': resource_id,
            'operation': 'VERIFY_RECORD_ABSENT',
            'state': 'ABSENT',
            'evidence_id': '',
        }]
    elif op == 'REPORT_EXPOSED_PII':
        category = _infer_category_from_system_resource(system_id, resource_id)
        action = CATEGORY_ACTION.get(category, 'REDACT')
        if action in ('ANONYMIZE',):
            return [{
                'phase': 'VERIFICATION',
                'system_id': system_id,
                'resource_id': resource_id,
                'operation': 'VERIFY_RECORD_ANONYMIZED',
                'state': 'ANONYMIZED',
                'evidence_id': '',
            }]
        else:
            return [{
                'phase': 'VERIFICATION',
                'system_id': system_id,
                'resource_id': resource_id,
                'operation': 'VERIFY_RECORD_REDACTED',
                'state': 'REDACTED',
                'evidence_id': '',
            }]
    elif op == 'REPORT_ACTIVE_DATA_FLOW':
        return [{
            'phase': 'VERIFICATION',
            'system_id': system_id,
            'resource_id': resource_id,
            'operation': 'VERIFY_DATA_FLOW_DISABLED',
            'state': 'DISABLED',
            'evidence_id': '',
        }]
    elif op == 'REPORT_RESTORE_RISK':
        return [{
            'phase': 'VERIFICATION',
            'system_id': system_id,
            'resource_id': resource_id,
            'operation': 'VERIFY_RESTORE_BLOCKED',
            'state': 'BLOCKED',
            'evidence_id': '',
        }]
    return []


def _infer_category_from_system_resource(system_id, resource_id):
    """Infer data category from system_id and resource_id."""
    if system_id == 'analytics_platform' or resource_id.startswith('analytics_'):
        return 'ANALYTICS_PROFILE'
    if system_id == 'support_platform' or resource_id.startswith('support_'):
        return 'SUPPORT_MESSAGE'
    if system_id == 'identity_service' or resource_id.startswith('tombstone_'):
        return 'ACCOUNT_TOMBSTONE'
    if system_id == 'notification_service' or resource_id.startswith('email_log_'):
        return 'EMAIL_DELIVERY_LOG'
    if resource_id.startswith('account_'):
        return 'USER_PROFILE'
    if resource_id.startswith('search_'):
        return 'SEARCH_INDEX_ENTRY'
    if resource_id.startswith('export_'):
        return 'USER_EXPORT'
    if resource_id.startswith('data_flow_'):
        return 'DATA_FLOW'
    if resource_id.startswith('backup_'):
        return 'BACKUP_ARCHIVE'
    if resource_id.startswith('audit_record_'):
        return 'SECURITY_AUDIT_LOG'
    if resource_id.startswith('marketing_'):
        return 'MARKETING_PROFILE'
    return 'USER_PROFILE'
