"""Evidence loaders: parse all evidence formats into Observation dicts."""
import csv
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict


def load_evidence_manifest(path):
    """Load evidence_files.csv into a list of dicts with file_id, file_path, captured_at."""
    with open(path, encoding='utf-8') as f:
        return list(csv.DictReader(f))


def load_all_evidence(manifest, dataset_dir):
    """Parse all evidence files. Returns dict: file_id -> list of Observation dicts.

    Each Observation:
      file_id, captured_at, system_id, resource_id, category, state,
      identifiers (dict with user_id, email, phone, email_hash keys),
      raw (optional extra data)
    """
    all_obs = {}
    error_count = 0
    for entry in manifest:
        file_id = entry['file_id']
        file_path = os.path.join(dataset_dir, entry['file_path'])
        captured_at = entry['captured_at']

        try:
            ext = file_path.rsplit('.', 1)[-1].lower()
            fname = os.path.basename(file_path).lower()

            if ext == 'sql':
                obs = _load_sql(file_path, file_id, captured_at)
            elif ext == 'json':
                obs = _load_json(file_path, file_id, captured_at)
            elif ext == 'log':
                obs = _load_log(file_path, file_id, captured_at, fname)
            elif ext == 'txt':
                obs = _load_txt(file_path, file_id, captured_at)
            elif ext == 'pdf':
                obs = _load_pdf(file_path, file_id, captured_at)
            elif ext == 'png':
                obs = _load_png(file_path, file_id, captured_at)
            else:
                obs = []

            all_obs[file_id] = obs
        except Exception as e:
            error_count += 1
            all_obs[file_id] = []
            print(f"WARN: Failed to load {file_id} ({file_path}): {e}", file=sys.stderr)

    if error_count:
        print(f"Evidence load errors: {error_count}", file=sys.stderr)
    return all_obs


# ─── SQL loader ──────────────────────────────────────────────────────────

def _load_sql(path, file_id, captured_at):
    """Load SQL evidence into in-memory SQLite and extract observations."""
    with open(path, encoding='utf-8') as f:
        sql = f.read()

    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(sql)
    except Exception as e:
        print(f"WARN: SQL parse error in {file_id}: {e}", file=sys.stderr)
        return []

    obs = []
    tables = [r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

    for table in tables:
        if table == 'snapshot_scope':
            continue
        rows = conn.execute(f'SELECT * FROM "{table}"').fetchall()
        cols = [d[0] for d in conn.execute(f'SELECT * FROM "{table}" LIMIT 0').description]

        for row in rows:
            row_dict = dict(zip(cols, row))
            ob = _sql_row_to_obs(table, row_dict, file_id, captured_at)
            if ob:
                obs.append(ob)

    # Handle topology snapshots: detect replication drift
    # Primary vs replica tables (customer_data_primary, *_replica, *_regional, etc.)
    _detect_topology_drift(conn, tables, obs, file_id, captured_at)

    conn.close()
    return obs


def _sql_row_to_obs(table, row, file_id, captured_at):
    """Convert a SQL row to an Observation based on table name."""
    resource_id = row.get('resource_id', '')
    identifiers = _extract_identifiers_from_row(row)

    tl = table.lower()

    # Per-system tables
    if 'customer_profiles' in tl and 'failover' not in tl and 'primary' not in tl:
        return _make_obs(file_id, captured_at, 'account_service', resource_id,
                         'USER_PROFILE', _profile_state(row), identifiers, row)

    if 'failover' in tl and 'profiles' in tl:
        return _make_obs(file_id, captured_at, 'account_service', resource_id,
                         'USER_PROFILE', 'PRESENT', identifiers, row,
                         replica_type='failover_replica')

    if 'primary' in tl and 'profiles' in tl:
        return _make_obs(file_id, captured_at, 'account_service', resource_id,
                         'USER_PROFILE', 'PRESENT', identifiers, row,
                         replica_type='primary')

    if 'search_documents' in tl and 'primary' not in tl:
        return _make_obs(file_id, captured_at, 'search_service', resource_id,
                         'SEARCH_INDEX_ENTRY', 'PRESENT', identifiers, row)

    if 'search_documents_primary' in tl:
        return _make_obs(file_id, captured_at, 'search_service', resource_id,
                         'SEARCH_INDEX_ENTRY', 'PRESENT', identifiers, row,
                         replica_type='primary')

    if 'analytics_profiles' in tl:
        state = _analytics_state(row)
        return _make_obs(file_id, captured_at, 'analytics_platform', resource_id,
                         'ANALYTICS_PROFILE', state, identifiers, row)

    if 'support_records' in tl:
        state = _support_state(row)
        return _make_obs(file_id, captured_at, 'support_platform', resource_id,
                         'SUPPORT_MESSAGE', state, identifiers, row)

    if 'customer_exports' in tl:
        return _make_obs(file_id, captured_at, 'export_service', resource_id,
                         'USER_EXPORT', 'PRESENT', identifiers, row)

    if 'connector_subscriptions' in tl:
        enabled = row.get('enabled', 0)
        state = 'ACTIVE' if enabled == 1 or enabled == '1' or enabled is True else 'DISABLED'
        return _make_obs(file_id, captured_at, 'integration_service', resource_id,
                         'DATA_FLOW', state, identifiers, row)

    if 'backup_restore' in tl:
        restore = row.get('restore_allowed', 0)
        state = 'ACTIVE' if restore == 1 or restore == '1' or restore is True else 'BLOCKED'
        return _make_obs(file_id, captured_at, 'backup_service', resource_id,
                         'BACKUP_ARCHIVE', state, identifiers, row)

    if 'security_audit' in tl:
        return _make_obs(file_id, captured_at, 'security_service', resource_id,
                         'SECURITY_AUDIT_LOG', 'PRESENT', identifiers, row)

    # Topology tables (customer_data_primary, *_replica, etc.)
    if 'customer_data' in tl:
        return _parse_topology_row(table, row, file_id, captured_at)

    return None


def _detect_topology_drift(conn, tables, obs, file_id, captured_at):
    """Detect rows present in replica but not primary (replication drift)."""
    # Find primary and replica table pairs
    primaries = [t for t in tables if 'primary' in t.lower() and t.lower() != 'snapshot_scope']
    replicas = [t for t in tables if any(x in t.lower() for x in ['replica', 'regional', 'reporting', 'failover'])
                and t.lower() != 'snapshot_scope']

    if not primaries:
        return

    # For profile-type topology tables, we already handle in _sql_row_to_obs
    # For customer_data_ tables, detect drift between primary and replicas
    for primary_t in primaries:
        primary_rows = {}
        try:
            rows = conn.execute(f'SELECT * FROM "{primary_t}"').fetchall()
            cols = [d[0] for d in conn.execute(f'SELECT * FROM "{primary_t}" LIMIT 0').description]
            for row in rows:
                rd = dict(zip(cols, row))
                rid = _extract_resource_id_from_topology(rd)
                if rid:
                    primary_rows[rid] = rd
        except:
            continue

        base = primary_t.lower().replace('_primary', '')

        for replica_t in replicas:
            if not replica_t.lower().startswith(base):
                continue
            try:
                r_rows = conn.execute(f'SELECT * FROM "{replica_t}"').fetchall()
                r_cols = [d[0] for d in conn.execute(f'SELECT * FROM "{replica_t}" LIMIT 0').description]
                for row in r_rows:
                    rd = dict(zip(r_cols, row))
                    rid = _extract_resource_id_from_topology(rd)
                    if rid and rid not in primary_rows:
                        # Drift: row in replica but not primary
                        # Already handled as individual observations
                        pass
            except:
                continue


def _extract_resource_id_from_topology(row):
    """Extract resource_id from a topology row (may be in record_json)."""
    if 'resource_id' in row:
        return row['resource_id']
    if 'record_json' in row:
        try:
            rec = json.loads(row['record_json'])
            return rec.get('resource_id')
        except:
            pass
    return None


def _parse_topology_row(table, row, file_id, captured_at):
    """Parse a customer_data_* topology table row."""
    tl = table.lower()

    # Determine if this is a record_json table
    if 'record_json' in row:
        try:
            rec = json.loads(row['record_json'])
        except:
            return None
    else:
        rec = row

    resource_id = rec.get('resource_id', row.get('resource_id', ''))
    identifiers = _extract_identifiers_from_row(rec)

    # Determine system from resource_id prefix or table name
    system_id, category = _infer_system_from_resource(resource_id, tl, rec)

    replica_type = None
    if 'primary' in tl:
        replica_type = 'primary'
    elif 'replica' in tl or 'regional' in tl or 'reporting' in tl or 'failover' in tl:
        replica_type = 'replica'

    state = 'PRESENT'
    if category == 'ANALYTICS_PROFILE':
        state = _analytics_state(rec)
    elif category == 'SUPPORT_MESSAGE':
        state = _support_state(rec)
    elif category == 'DATA_FLOW':
        enabled = rec.get('enabled')
        state = 'ACTIVE' if enabled in (1, '1', True, 'true') else 'DISABLED'
    elif category == 'BACKUP_ARCHIVE':
        restore = rec.get('restore_allowed')
        state = 'ACTIVE' if restore in (1, '1', True, 'true') else 'BLOCKED'

    return _make_obs(file_id, captured_at, system_id, resource_id, category,
                     state, identifiers, rec, replica_type=replica_type)


def _infer_system_from_resource(resource_id, table_lower, rec=None):
    """Infer system_id and category from resource_id prefix."""
    rid = resource_id.lower() if resource_id else ''

    if rid.startswith('account_'):
        return 'account_service', 'USER_PROFILE'
    elif rid.startswith('search_'):
        return 'search_service', 'SEARCH_INDEX_ENTRY'
    elif rid.startswith('analytics_'):
        return 'analytics_platform', 'ANALYTICS_PROFILE'
    elif rid.startswith('support_'):
        return 'support_platform', 'SUPPORT_MESSAGE'
    elif rid.startswith('export_'):
        return 'export_service', 'USER_EXPORT'
    elif rid.startswith('data_flow_'):
        return 'integration_service', 'DATA_FLOW'
    elif rid.startswith('backup_'):
        return 'backup_service', 'BACKUP_ARCHIVE'
    elif rid.startswith('audit_record_'):
        return 'security_service', 'SECURITY_AUDIT_LOG'
    elif rid.startswith('tombstone_'):
        return 'identity_service', 'ACCOUNT_TOMBSTONE'
    elif rid.startswith('marketing_'):
        return 'marketing_service', 'MARKETING_PROFILE'
    elif rid.startswith('cache_'):
        return 'cache_service', 'CACHE_ENTRY'
    elif rid.startswith('email_log_') or rid.startswith('delivery_'):
        return 'notification_service', 'EMAIL_DELIVERY_LOG'

    return 'unknown_service', 'UNKNOWN'


def _profile_state(row):
    """Determine profile state from account_status."""
    status = (row.get('account_status') or '').upper()
    if status == 'DELETED':
        return 'ABSENT'
    if status == 'DELETION_PENDING':
        return 'PRESENT'
    return 'PRESENT'


def _analytics_state(row):
    """Determine if analytics profile is anonymized or still identifiable."""
    # Check if any direct identifiers remain
    email = row.get('email')
    phone = row.get('phone')
    email_hash = row.get('email_hash')
    customer_ref = row.get('customer_reference')

    has_pii = False
    for v in [email, phone, email_hash]:
        if v is not None and str(v).strip() and str(v).strip().lower() != 'none':
            has_pii = True
            break

    if has_pii:
        return 'IDENTIFIABLE'

    # customer_reference alone: if it's None/null, it's anonymized
    if customer_ref is not None and str(customer_ref).strip() and str(customer_ref).strip().lower() != 'none':
        return 'IDENTIFIABLE'

    return 'ANONYMIZED'


def _support_state(row):
    """Determine support record state."""
    # Check for PII in requester fields
    email = row.get('requester_email')
    phone = row.get('requester_phone')
    name = row.get('requester_name')

    has_pii = False
    for v in [email, phone, name]:
        if v is not None and str(v).strip() and str(v).strip().lower() != 'none':
            has_pii = True
            break

    if has_pii:
        return 'IDENTIFIABLE'
    return 'REDACTED'


def _extract_identifiers_from_row(row):
    """Extract identifier fields from a row dict."""
    ids = {}

    # user_id / customer_reference / subject_reference
    for k in ('user_id', 'customer_reference', 'subject_reference'):
        v = row.get(k)
        if v and str(v).strip() and str(v).strip().lower() != 'none':
            ids['user_id'] = str(v).strip()
            break

    for k in ('email', 'owner_email', 'requester_email', 'customer_email'):
        v = row.get(k)
        if v and str(v).strip() and str(v).strip().lower() != 'none':
            ids['email'] = str(v).strip().lower()
            break

    for k in ('phone', 'owner_phone', 'requester_phone'):
        v = row.get(k)
        if v and str(v).strip() and str(v).strip().lower() != 'none':
            ids['phone'] = re.sub(r'[^0-9+]', '', str(v))
            break

    v = row.get('email_hash')
    if v and str(v).strip() and str(v).strip().lower() != 'none':
        ids['email_hash'] = str(v).strip()

    return ids


def _make_obs(file_id, captured_at, system_id, resource_id, category, state,
              identifiers, raw, replica_type=None):
    ob = {
        'file_id': file_id,
        'captured_at': captured_at,
        'system_id': system_id,
        'resource_id': resource_id,
        'category': category,
        'state': state,
        'identifiers': identifiers,
        'replica_type': replica_type,
    }
    # Store retention info for security records
    if category == 'SECURITY_AUDIT_LOG':
        ob['retention_until'] = raw.get('retention_until', '')
    if category == 'BACKUP_ARCHIVE':
        ob['archive_key'] = raw.get('archive_key', '')
    if category == 'DATA_FLOW':
        ob['connector_name'] = raw.get('connector_name', '')
    if category == 'ACCOUNT_TOMBSTONE':
        # Check if tombstone still has PII
        has_pii = False
        for k in ('name', 'email', 'phone', 'email_hash'):
            v = raw.get(k)
            if v is not None and str(v).strip() and str(v).strip().lower() != 'none':
                has_pii = True
                break
        ob['tombstone_has_pii'] = has_pii
    if category == 'SUPPORT_MESSAGE':
        ob['message_excerpt'] = raw.get('message_excerpt', '')
    return ob


# ─── JSON loader ──────────────────────────────────────────────────────────

def _load_json(path, file_id, captured_at):
    with open(path, encoding='utf-8') as f:
        data = json.load(f)

    fname = os.path.basename(path).lower()

    if 'snapshot_bundle' in fname:
        return _parse_snapshot_bundle(data, file_id, captured_at)
    elif 'service_resource_export' in fname:
        return _parse_service_resource_export(data, file_id, captured_at)
    elif 'analytics_report' in fname:
        return _parse_analytics_report(data, file_id, captured_at)
    elif 'export_jobs' in fname or 'export_manifest' in fname:
        return _parse_export_json(data, file_id, captured_at)
    elif 'connector_configurations' in fname:
        return _parse_connector_config(data, file_id, captured_at)
    elif 'security_audit_ledger' in fname:
        return _parse_security_ledger(data, file_id, captured_at)
    else:
        return _parse_generic_json(data, file_id, captured_at)


def _parse_snapshot_bundle(data, file_id, captured_at):
    """Parse customer_data_snapshot_bundle JSON."""
    obs = []
    for snapshot in data.get('snapshots', []):
        system = snapshot.get('data_store', '')
        collection = snapshot.get('collection', '')
        for rec in snapshot.get('records', []):
            resource_id = rec.get('resource_id', '')
            identifiers = _extract_identifiers_from_row(rec)

            system_id, category = _infer_system_category_from_collection(system, collection, resource_id)

            state = 'PRESENT'
            if category == 'ANALYTICS_PROFILE':
                state = _analytics_state(rec)
            elif category == 'SUPPORT_MESSAGE':
                state = _support_state(rec)
            elif category == 'ACCOUNT_TOMBSTONE':
                state = 'PRESENT'

            ob = _make_obs(file_id, captured_at, system_id, resource_id,
                           category, state, identifiers, rec)
            obs.append(ob)
    return obs


def _infer_system_category_from_collection(system, collection, resource_id):
    """Infer system_id and category from snapshot data_store and collection."""
    cl = collection.lower()
    sl = system.lower()

    if 'deleted_customer_references' in cl or 'tombstone' in resource_id.lower():
        return 'identity_service', 'ACCOUNT_TOMBSTONE'
    if 'customer_profiles' in cl or 'account' in cl:
        return 'account_service', 'USER_PROFILE'
    if 'search' in cl:
        return 'search_service', 'SEARCH_INDEX_ENTRY'
    if 'analytics' in cl:
        return 'analytics_platform', 'ANALYTICS_PROFILE'
    if 'support' in cl:
        return 'support_platform', 'SUPPORT_MESSAGE'
    if 'export' in cl:
        return 'export_service', 'USER_EXPORT'
    if 'connector' in cl:
        return 'integration_service', 'DATA_FLOW'
    if 'backup' in cl or 'restore' in cl:
        return 'backup_service', 'BACKUP_ARCHIVE'
    if 'security' in cl or 'audit' in cl:
        return 'security_service', 'SECURITY_AUDIT_LOG'
    if 'marketing' in cl:
        return 'marketing_service', 'MARKETING_PROFILE'

    return _infer_system_from_resource(resource_id, '', None)


def _parse_service_resource_export(data, file_id, captured_at):
    """Parse service_resource_export JSON (evidence_92 style)."""
    obs = []
    se = data.get('service_exports', {})
    if not isinstance(se, dict):
        return obs

    for svc_name, svc_data in se.items():
        if not isinstance(svc_data, dict):
            continue
        for sub_key, records in svc_data.items():
            if not isinstance(records, list):
                continue
            for rec in records:
                resource_id = rec.get('resource_id', '')
                observed_at = rec.get('observed_at', captured_at)
                identifiers = _extract_identifiers_from_row(rec)

                system_id = _map_service_name(svc_name)
                category = _infer_category_from_sub_key(sub_key, resource_id)

                state = _determine_state_from_export_record(rec, category, sub_key)

                ob = _make_obs(file_id, observed_at, system_id, resource_id,
                               category, state, identifiers, rec)
                obs.append(ob)
    return obs


def _map_service_name(name):
    mapping = {
        'account_service': 'account_service',
        'analytics_platform': 'analytics_platform',
        'backup_service': 'backup_service',
        'export_service': 'export_service',
        'integration_service': 'integration_service',
        'search_service': 'search_service',
        'security_service': 'security_service',
        'support_platform': 'support_platform',
        'marketing_service': 'marketing_service',
        'notification_service': 'notification_service',
        'identity_service': 'identity_service',
    }
    return mapping.get(name, name)


def _infer_category_from_sub_key(sub_key, resource_id):
    sk = sub_key.lower()
    if 'profile_lookup' in sk or 'profiles' == sk:
        if resource_id.startswith('analytics_'):
            return 'ANALYTICS_PROFILE'
        return 'USER_PROFILE'
    if 'index_quer' in sk:
        return 'SEARCH_INDEX_ENTRY'
    if 'profiles' in sk:
        if resource_id.startswith('analytics_'):
            return 'ANALYTICS_PROFILE'
        return 'USER_PROFILE'
    if 'restore' in sk or 'backup' in sk:
        return 'BACKUP_ARCHIVE'
    if 'export' in sk:
        return 'USER_EXPORT'
    if 'connector' in sk:
        return 'DATA_FLOW'
    if 'audit' in sk:
        return 'SECURITY_AUDIT_LOG'
    if 'ticket' in sk or 'support' in sk:
        return 'SUPPORT_MESSAGE'
    if 'marketing' in sk:
        return 'MARKETING_PROFILE'

    return _infer_system_from_resource(resource_id, '', None)[1]


def _determine_state_from_export_record(rec, category, sub_key):
    """Determine state from a service_resource_export record."""
    # Account lookups: status_code 404 = ABSENT, profile null = ABSENT
    if category == 'USER_PROFILE':
        if rec.get('status_code') == 404 or rec.get('profile') is None:
            return 'ABSENT'
        return 'PRESENT'

    if category == 'SEARCH_INDEX_ENTRY':
        hits = rec.get('hits', {})
        if isinstance(hits, dict):
            total = hits.get('total', 0)
            if total == 0:
                return 'ABSENT'
            docs = hits.get('documents', [])
            if docs:
                return 'PRESENT'
        result = rec.get('result', '')
        if result == 'miss' or result == 'not_found':
            return 'ABSENT'
        return 'PRESENT'

    if category == 'ANALYTICS_PROFILE':
        return _analytics_state(rec)

    if category == 'SUPPORT_MESSAGE':
        return _support_state(rec)

    if category == 'BACKUP_ARCHIVE':
        restore = rec.get('restore_allowed')
        if restore in (False, 0, '0', 'false'):
            return 'BLOCKED'
        return 'ACTIVE'

    if category == 'DATA_FLOW':
        enabled = rec.get('enabled')
        if enabled in (False, 0, '0', 'false'):
            return 'DISABLED'
        return 'ACTIVE'

    if category == 'USER_EXPORT':
        available = rec.get('available')
        if available in (False, 0, '0', 'false'):
            return 'ABSENT'
        return 'PRESENT'

    if category == 'SECURITY_AUDIT_LOG':
        return 'PRESENT'

    return 'PRESENT'


def _parse_analytics_report(data, file_id, captured_at):
    """Parse customer_analytics_report JSON."""
    obs = []
    # May have profiles list or report structure
    profiles = data.get('profiles', data.get('records', []))
    if isinstance(profiles, list):
        for rec in profiles:
            resource_id = rec.get('resource_id', '')
            identifiers = _extract_identifiers_from_row(rec)
            state = _analytics_state(rec)
            ob = _make_obs(file_id, captured_at, 'analytics_platform', resource_id,
                           'ANALYTICS_PROFILE', state, identifiers, rec)
            obs.append(ob)
    return obs


def _parse_export_json(data, file_id, captured_at):
    """Parse export jobs/manifest JSON."""
    obs = []
    jobs = data.get('jobs', data.get('exports', data.get('records', [])))
    if isinstance(jobs, list):
        for rec in jobs:
            resource_id = rec.get('resource_id', rec.get('export_id', ''))
            identifiers = _extract_identifiers_from_row(rec)
            state = 'PRESENT'
            if rec.get('status') in ('deleted', 'purged', 'removed'):
                state = 'ABSENT'
            ob = _make_obs(file_id, captured_at, 'export_service', resource_id,
                           'USER_EXPORT', state, identifiers, rec)
            obs.append(ob)
    return obs


def _parse_connector_config(data, file_id, captured_at):
    """Parse connector_configurations JSON."""
    obs = []
    conns = data.get('connectors', data.get('configurations', data.get('records', [])))
    if isinstance(conns, list):
        for rec in conns:
            resource_id = rec.get('resource_id', rec.get('connector_id', ''))
            identifiers = _extract_identifiers_from_row(rec)
            enabled = rec.get('enabled', rec.get('active', False))
            state = 'ACTIVE' if enabled in (True, 1, '1', 'true') else 'DISABLED'
            ob = _make_obs(file_id, captured_at, 'integration_service', resource_id,
                           'DATA_FLOW', state, identifiers, rec)
            obs.append(ob)
    return obs


def _parse_security_ledger(data, file_id, captured_at):
    """Parse security_audit_ledger JSON."""
    obs = []
    records = data.get('audit_entries', data.get('records', data.get('entries', [])))
    if isinstance(records, list):
        for rec in records:
            resource_id = rec.get('resource_id', rec.get('entry_id', ''))
            identifiers = _extract_identifiers_from_row(rec)
            ob = _make_obs(file_id, captured_at, 'security_service', resource_id,
                           'SECURITY_AUDIT_LOG', 'PRESENT', identifiers, rec)
            obs.append(ob)
    return obs


def _parse_generic_json(data, file_id, captured_at):
    """Fallback JSON parser."""
    obs = []
    # Try common structures
    if isinstance(data, list):
        for rec in data:
            if isinstance(rec, dict) and 'resource_id' in rec:
                resource_id = rec['resource_id']
                identifiers = _extract_identifiers_from_row(rec)
                system_id, category = _infer_system_from_resource(resource_id, '', rec)
                ob = _make_obs(file_id, captured_at, system_id, resource_id,
                               category, 'PRESENT', identifiers, rec)
                obs.append(ob)
    elif isinstance(data, dict):
        # Try each key as a potential list of records
        for k, v in data.items():
            if isinstance(v, list):
                for rec in v:
                    if isinstance(rec, dict) and 'resource_id' in rec:
                        resource_id = rec['resource_id']
                        identifiers = _extract_identifiers_from_row(rec)
                        system_id, category = _infer_system_from_resource(resource_id, '', rec)
                        ob = _make_obs(file_id, captured_at, system_id, resource_id,
                                       category, 'PRESENT', identifiers, rec)
                        obs.append(ob)
    return obs


# ─── Log loader ──────────────────────────────────────────────────────────

def _load_log(path, file_id, captured_at, fname):
    """Parse log files of various formats."""
    with open(path, encoding='utf-8') as f:
        lines = f.readlines()

    if 'resource_lookup_trace' in fname:
        return _parse_resource_lookup_trace(lines, file_id, captured_at)
    elif 'service_events' in fname or 'structured_service_events' in fname:
        return _parse_service_events_log(lines, file_id, captured_at)
    elif 'search_index_diagnostic' in fname:
        return _parse_search_diagnostic_log(lines, file_id, captured_at)
    elif 'support_replica' in fname:
        return _parse_support_replica_log(lines, file_id, captured_at)
    elif 'syslog' in fname:
        return _parse_syslog(lines, file_id, captured_at)
    elif 'application_trace' in fname:
        return _parse_application_trace(lines, file_id, captured_at)
    elif 'operations_stream' in fname:
        return _parse_operations_stream(lines, file_id, captured_at)
    elif 'cloud_runtime' in fname:
        return _parse_cloud_runtime(lines, file_id, captured_at)
    elif 'notification_delivery' in fname:
        return _parse_notification_delivery(lines, file_id, captured_at)
    else:
        return _parse_generic_log(lines, file_id, captured_at)


def _parse_kv(line):
    """Parse key=value pairs from a log line, handling quoted values."""
    result = {}
    # Match key=value or key="value with spaces"
    for m in re.finditer(r'(\w+)=(\"[^\"]*\"|\S+)', line):
        k = m.group(1)
        v = m.group(2).strip('"')
        result[k] = v
    return result


def _parse_resource_lookup_trace(lines, file_id, captured_at):
    """Parse resource_lookup_trace log format."""
    obs = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        kv = _parse_kv(line)
        event = kv.get('event', '')
        resource_id = kv.get('resource_id', '')

        if not resource_id:
            continue

        # Profile lookup completed
        if event == 'profile_lookup_completed':
            rows = int(kv.get('rows', '0'))
            state = 'ABSENT' if rows == 0 else 'PRESENT'
            identifiers = {}
            lk = kv.get('lookup_key', '')
            if lk and '@' in lk:
                identifiers['email'] = lk.lower()
            elif lk and lk.startswith('user_'):
                identifiers['user_id'] = lk
            ob = _make_obs(file_id, captured_at, 'account_service', resource_id,
                           'USER_PROFILE', state, identifiers, kv)
            obs.append(ob)

        elif event == 'index_query_completed':
            result = kv.get('result', '')
            state = 'PRESENT' if result == 'hit' else 'ABSENT'
            identifiers = {}
            lk = kv.get('lookup_key', kv.get('correlation_key', ''))
            email_val = kv.get('email', '')
            customer_ref = kv.get('customer_reference', '')
            if lk and '@' in lk:
                identifiers['email'] = lk.lower()
            if email_val and '@' in email_val:
                identifiers['email'] = email_val.lower()
            if customer_ref and customer_ref != 'null' and customer_ref.startswith('user_'):
                identifiers['user_id'] = customer_ref
            ob = _make_obs(file_id, captured_at, 'search_service', resource_id,
                           'SEARCH_INDEX_ENTRY', state, identifiers, kv)
            obs.append(ob)

        elif event == 'connector_config_read_completed' or event == 'connector_heartbeat':
            enabled = kv.get('enabled', 'false')
            state = 'ACTIVE' if enabled == 'true' else 'DISABLED'
            identifiers = {}
            lk = kv.get('lookup_key', kv.get('subject_key', ''))
            ce = kv.get('customer_email', '')
            cr = kv.get('customer_reference', '')
            if lk and '@' in lk:
                identifiers['email'] = lk.lower()
            elif lk and lk.startswith('user_'):
                identifiers['user_id'] = lk
            if ce and ce != 'null' and '@' in ce:
                identifiers['email'] = ce.lower()
            if cr and cr != 'null' and cr.startswith('user_'):
                identifiers['user_id'] = cr
            ob = _make_obs(file_id, captured_at, 'integration_service', resource_id,
                           'DATA_FLOW', state, identifiers, kv)
            obs.append(ob)

        elif event == 'restore_policy_read_completed' or event == 'restore_candidate_evaluated':
            restore = kv.get('restore_allowed', kv.get('deletion_block', 'false'))
            if event == 'restore_candidate_evaluated':
                # deletion_block=false means restore IS allowed
                db = kv.get('deletion_block', 'false')
                state = 'BLOCKED' if db == 'true' else 'ACTIVE'
            else:
                state = 'BLOCKED' if restore == 'false' else 'ACTIVE'
            identifiers = {}
            lk = kv.get('lookup_key', '')
            ce = kv.get('customer_email', '')
            cr = kv.get('customer_reference', '')
            if lk and '@' in lk:
                identifiers['email'] = lk.lower()
            elif lk and lk.startswith('user_'):
                identifiers['user_id'] = lk
            if ce and ce != 'null' and '@' in ce:
                identifiers['email'] = ce.lower()
            if cr and cr != 'null' and cr.startswith('user_'):
                identifiers['user_id'] = cr
            ob = _make_obs(file_id, captured_at, 'backup_service', resource_id,
                           'BACKUP_ARCHIVE', state, identifiers, kv)
            obs.append(ob)

        elif event == 'audit_record_read_completed':
            identifiers = {}
            sr = kv.get('subject_reference', kv.get('correlation_key', ''))
            if sr and sr.startswith('user_'):
                identifiers['user_id'] = sr
            retention = kv.get('retention_until', '')
            ob = _make_obs(file_id, captured_at, 'security_service', resource_id,
                           'SECURITY_AUDIT_LOG', 'PRESENT', identifiers, kv)
            ob['retention_until'] = retention
            obs.append(ob)

        elif event == 'support_ticket_read_completed':
            identifiers = {}
            cr = kv.get('customer_reference', '')
            re_email = kv.get('requester_email', '')
            re_name = kv.get('requester_name', '')
            re_phone = kv.get('requester_phone', '')
            lk = kv.get('lookup_key', '')
            if cr and cr != 'null' and cr.startswith('user_'):
                identifiers['user_id'] = cr
            if re_email and re_email != 'null' and '@' in re_email:
                identifiers['email'] = re_email.lower()
            if lk and '@' in lk:
                identifiers['email'] = lk.lower()

            # Determine state: check if PII is present
            has_pii = False
            for v in [re_email, re_name, re_phone]:
                if v and v != 'null':
                    has_pii = True
                    break
            state = 'IDENTIFIABLE' if has_pii else 'REDACTED'
            ob = _make_obs(file_id, captured_at, 'support_platform', resource_id,
                           'SUPPORT_MESSAGE', state, identifiers, kv)
            obs.append(ob)

        elif event == 'analytics_identity_scan' or event == 'contact_lookup_completed':
            identifiers = {}
            mv = kv.get('matched_value', '')
            cr = kv.get('correlation_key', '')
            if mv and '@' in mv:
                identifiers['email'] = mv.lower()
            if cr and cr.startswith('user_'):
                identifiers['user_id'] = cr
            elif cr and len(cr) > 20:  # likely email_hash
                identifiers['email_hash'] = cr

            di = kv.get('direct_identifiers', '0')
            state = 'IDENTIFIABLE' if di != '0' else 'ANONYMIZED'
            ob = _make_obs(file_id, captured_at, 'analytics_platform', resource_id,
                           'ANALYTICS_PROFILE', state, identifiers, kv)
            obs.append(ob)

        elif event == 'export_download_check_completed':
            identifiers = {}
            available = kv.get('available', 'false')
            state = 'PRESENT' if available == 'true' else 'ABSENT'
            ob = _make_obs(file_id, captured_at, 'export_service', resource_id,
                           'USER_EXPORT', state, identifiers, kv)
            obs.append(ob)

        elif event == 'message_pii_scan':
            identifiers = {}
            mv = kv.get('matched_value', '')
            if mv and '@' in mv:
                identifiers['email'] = mv.lower()
            ob = _make_obs(file_id, captured_at, 'support_platform', resource_id,
                           'SUPPORT_MESSAGE', 'IDENTIFIABLE', identifiers, kv)
            obs.append(ob)

        elif event == 'tombstone_read_completed':
            identifiers = {}
            sr = kv.get('subject_reference', '')
            if sr and sr.startswith('user_'):
                identifiers['user_id'] = sr
            pii = kv.get('pii_fields_present', '0')
            has_pii = pii != '0' and pii != 'false'
            ob = _make_obs(file_id, captured_at, 'identity_service', resource_id,
                           'ACCOUNT_TOMBSTONE', 'PRESENT', identifiers, kv)
            ob['tombstone_has_pii'] = has_pii
            obs.append(ob)

    return obs


def _parse_service_events_log(lines, file_id, captured_at):
    """Parse service_events / structured_service_events log format."""
    obs = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        kv = _parse_kv(line)
        event = kv.get('event', '')
        resource_id = kv.get('resource_id', '')

        if not resource_id:
            continue

        service = kv.get('service', '')

        if event == 'profile_lookup_completed':
            rows = int(kv.get('rows', '0'))
            state = 'ABSENT' if rows == 0 else 'PRESENT'
            identifiers = {}
            lk = kv.get('lookup_key', '')
            if lk and '@' in lk:
                identifiers['email'] = lk.lower()
            ob = _make_obs(file_id, captured_at, 'account_service', resource_id,
                           'USER_PROFILE', state, identifiers, kv)
            obs.append(ob)

        elif event == 'index_query_completed':
            result = kv.get('result', '')
            state = 'PRESENT' if result == 'hit' else 'ABSENT'
            identifiers = {}
            ck = kv.get('correlation_key', '')
            if ck and '@' in ck:
                identifiers['email'] = ck.lower()
            ob = _make_obs(file_id, captured_at, 'search_service', resource_id,
                           'SEARCH_INDEX_ENTRY', state, identifiers, kv)
            obs.append(ob)

        elif event == 'connector_heartbeat' or event == 'connector_config_read_completed':
            enabled = kv.get('enabled', 'false')
            state = 'ACTIVE' if enabled == 'true' else 'DISABLED'
            identifiers = {}
            sk = kv.get('subject_key', '')
            if sk and '@' in sk:
                identifiers['email'] = sk.lower()
            elif sk and sk.startswith('user_'):
                identifiers['user_id'] = sk
            ob = _make_obs(file_id, captured_at, 'integration_service', resource_id,
                           'DATA_FLOW', state, identifiers, kv)
            obs.append(ob)

        elif event == 'restore_candidate_evaluated':
            db = kv.get('deletion_block', 'false')
            state = 'BLOCKED' if db == 'true' else 'ACTIVE'
            identifiers = {}
            ob = _make_obs(file_id, captured_at, 'backup_service', resource_id,
                           'BACKUP_ARCHIVE', state, identifiers, kv)
            obs.append(ob)

        elif event == 'audit_record_read_completed':
            identifiers = {}
            sr = kv.get('correlation_key', kv.get('subject_reference', ''))
            if sr and sr.startswith('user_'):
                identifiers['user_id'] = sr
            ob = _make_obs(file_id, captured_at, 'security_service', resource_id,
                           'SECURITY_AUDIT_LOG', 'PRESENT', identifiers, kv)
            ob['retention_until'] = kv.get('retention_until', '')
            obs.append(ob)

        elif event == 'message_pii_scan':
            identifiers = {}
            mv = kv.get('matched_value', '')
            if mv and '@' in mv:
                identifiers['email'] = mv.lower()
            ob = _make_obs(file_id, captured_at, 'support_platform', resource_id,
                           'SUPPORT_MESSAGE', 'IDENTIFIABLE', identifiers, kv)
            obs.append(ob)

        elif event == 'analytics_identity_scan' or event == 'contact_lookup_completed':
            identifiers = {}
            mv = kv.get('matched_value', kv.get('correlation_key', ''))
            if mv and '@' in mv:
                identifiers['email'] = mv.lower()
            elif mv and len(mv) > 20:
                identifiers['email_hash'] = mv
            di = kv.get('direct_identifiers', '0')
            state = 'IDENTIFIABLE' if di != '0' else 'ANONYMIZED'
            ob = _make_obs(file_id, captured_at, 'analytics_platform', resource_id,
                           'ANALYTICS_PROFILE', state, identifiers, kv)
            obs.append(ob)

        elif event == 'export_download_check_completed':
            identifiers = {}
            available = kv.get('available', 'false')
            state = 'PRESENT' if available == 'true' else 'ABSENT'
            ob = _make_obs(file_id, captured_at, 'export_service', resource_id,
                           'USER_EXPORT', state, identifiers, kv)
            obs.append(ob)

        elif event == 'support_ticket_read_completed':
            identifiers = {}
            cr = kv.get('customer_reference', '')
            re_email = kv.get('requester_email', '')
            lk = kv.get('lookup_key', kv.get('subject_key', ''))
            if cr and cr != 'null' and cr.startswith('user_'):
                identifiers['user_id'] = cr
            if re_email and re_email != 'null' and '@' in re_email:
                identifiers['email'] = re_email.lower()
            if lk and '@' in lk:
                identifiers['email'] = lk.lower()
            re_name = kv.get('requester_name', '')
            re_phone = kv.get('requester_phone', '')
            has_pii = any(v and v != 'null' for v in [re_email, re_name, re_phone])
            state = 'IDENTIFIABLE' if has_pii else 'REDACTED'
            ob = _make_obs(file_id, captured_at, 'support_platform', resource_id,
                           'SUPPORT_MESSAGE', state, identifiers, kv)
            obs.append(ob)

        elif event == 'tombstone_read_completed':
            identifiers = {}
            sr = kv.get('subject_reference', '')
            if sr and sr.startswith('user_'):
                identifiers['user_id'] = sr
            pii = kv.get('pii_fields_present', '0')
            has_pii = pii != '0' and pii != 'false'
            ob = _make_obs(file_id, captured_at, 'identity_service', resource_id,
                           'ACCOUNT_TOMBSTONE', 'PRESENT', identifiers, kv)
            ob['tombstone_has_pii'] = has_pii
            obs.append(ob)

        elif event == 'restore_policy_read_completed':
            restore = kv.get('restore_allowed', 'false')
            state = 'BLOCKED' if restore == 'false' else 'ACTIVE'
            identifiers = {}
            cr = kv.get('customer_reference', '')
            if cr and cr != 'null' and cr.startswith('user_'):
                identifiers['user_id'] = cr
            ob = _make_obs(file_id, captured_at, 'backup_service', resource_id,
                           'BACKUP_ARCHIVE', state, identifiers, kv)
            obs.append(ob)

    return obs


def _parse_search_diagnostic_log(lines, file_id, captured_at):
    """Parse search_index_diagnostic log."""
    return _parse_service_events_log(lines, file_id, captured_at)


def _parse_support_replica_log(lines, file_id, captured_at):
    """Parse support_replica.log."""
    return _parse_service_events_log(lines, file_id, captured_at)


def _parse_syslog(lines, file_id, captured_at):
    return _parse_service_events_log(lines, file_id, captured_at)


def _parse_application_trace(lines, file_id, captured_at):
    return _parse_service_events_log(lines, file_id, captured_at)


def _parse_operations_stream(lines, file_id, captured_at):
    return _parse_service_events_log(lines, file_id, captured_at)


def _parse_cloud_runtime(lines, file_id, captured_at):
    return _parse_service_events_log(lines, file_id, captured_at)


def _parse_notification_delivery(lines, file_id, captured_at):
    """Parse notification_delivery log for email delivery records."""
    obs = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        kv = _parse_kv(line)
        event = kv.get('event', '')
        resource_id = kv.get('resource_id', '')

        if not resource_id:
            # Also look for general service events
            obs.extend(_parse_service_events_log([line], file_id, captured_at))
            continue

        if 'delivery' in event.lower() or 'notification' in event.lower() or 'email' in event.lower():
            identifiers = {}
            recipient = kv.get('recipient', kv.get('to_email', kv.get('email', '')))
            if recipient and '@' in recipient:
                identifiers['email'] = recipient.lower()
            ob = _make_obs(file_id, captured_at, 'notification_service', resource_id,
                           'EMAIL_DELIVERY_LOG', 'PRESENT', identifiers, kv)
            obs.append(ob)
        else:
            obs.extend(_parse_service_events_log([line], file_id, captured_at))

    return obs


def _parse_generic_log(lines, file_id, captured_at):
    return _parse_service_events_log(lines, file_id, captured_at)


# ─── TXT loader ──────────────────────────────────────────────────────────

def _load_txt(path, file_id, captured_at):
    """Parse customer_account_handover TXT format."""
    with open(path, encoding='utf-8') as f:
        content = f.read()

    obs = []
    for line in content.split('\n'):
        line = line.strip()
        if not line.startswith('- '):
            continue

        # Format: - timestamp | system | resource | CATEGORY | STATE | identifier
        parts = [p.strip() for p in line[2:].split('|')]
        if len(parts) < 6:
            continue

        ts, system_id, resource_id, category_str, state_str, identifier = parts[:6]

        # Map system names
        system_id = system_id.strip()

        # Map category
        category = category_str.strip()

        # Map state
        state = _map_handover_state(state_str.strip(), category)

        # Extract identifier
        identifiers = {}
        id_val = identifier.strip()
        if '@' in id_val:
            identifiers['email'] = id_val.lower()
        elif id_val.startswith('user_'):
            identifiers['user_id'] = id_val
        elif id_val != 'no direct identifier':
            pass  # unknown identifier format

        ob = _make_obs(file_id, captured_at, system_id, resource_id,
                       category, state, identifiers, {'raw_line': line})
        obs.append(ob)

    return obs


def _map_handover_state(state_str, category):
    """Map handover state strings to normalized states."""
    s = state_str.upper()
    if s == 'NOT_FOUND':
        return 'ABSENT'
    elif s == 'FOUND':
        return 'PRESENT'
    elif s == 'IDENTIFIABLE':
        return 'IDENTIFIABLE'
    elif s == 'ANONYMIZED':
        return 'ANONYMIZED'
    elif s == 'REDACTED':
        return 'REDACTED'
    elif s == 'ACTIVE':
        return 'ACTIVE'
    elif s == 'DISABLED':
        return 'DISABLED'
    elif s == 'BLOCKED':
        return 'BLOCKED'
    return s


# ─── PDF loader ──────────────────────────────────────────────────────────

def _load_pdf(path, file_id, captured_at):
    """Try to extract text from PDF using pdftotext or cached text."""
    cache_dir = os.path.join(os.path.dirname(__file__), 'cache')
    cache_file = os.path.join(cache_dir, f'{file_id}.txt')

    if os.path.exists(cache_file):
        with open(cache_file, encoding='utf-8') as f:
            text = f.read()
        return _parse_pdf_text(text, file_id, captured_at)

    # Try pdftotext
    try:
        import subprocess
        result = subprocess.run(['pdftotext', '-layout', path, '-'],
                                capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            text = result.stdout
            os.makedirs(cache_dir, exist_ok=True)
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(text)
            return _parse_pdf_text(text, file_id, captured_at)
    except (FileNotFoundError, Exception):
        pass

    # Try pypdf
    try:
        import pypdf
        reader = pypdf.PdfReader(path)
        text = ''
        for page in reader.pages:
            text += page.extract_text() + '\n'
        if text.strip():
            os.makedirs(cache_dir, exist_ok=True)
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(text)
            return _parse_pdf_text(text, file_id, captured_at)
    except ImportError:
        pass

    # Try PyMuPDF (fitz)
    try:
        import fitz
        doc = fitz.open(path)
        text = ''
        for page in doc:
            text += page.get_text() + '\n'
        doc.close()
        if text.strip():
            os.makedirs(cache_dir, exist_ok=True)
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(text)
            return _parse_pdf_text(text, file_id, captured_at)
    except ImportError:
        pass

    print(f"WARN: Cannot extract text from PDF {file_id} ({path})", file=sys.stderr)
    return []


def _parse_pdf_text(text, file_id, captured_at):
    """Parse extracted PDF text for observations."""
    obs = []

    # Look for handover-style lines
    for line in text.split('\n'):
        line = line.strip()
        if '|' in line and any(kw in line for kw in ['account_', 'search_', 'analytics_', 'support_',
                                                       'export_', 'data_flow_', 'backup_', 'audit_record_',
                                                       'tombstone_', 'marketing_']):
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 5:
                # Try to parse as handover format
                # Might be: ts | system | resource | category | state | identifier
                # or: resource | system | state | identifier
                try:
                    ts, system_id, resource_id, category, state_str = parts[:5]
                    identifier = parts[5] if len(parts) > 5 else ''
                    state = _map_handover_state(state_str, category)
                    identifiers = {}
                    if '@' in identifier:
                        identifiers['email'] = identifier.lower()
                    elif identifier.startswith('user_'):
                        identifiers['user_id'] = identifier
                    ob = _make_obs(file_id, captured_at, system_id, resource_id,
                                   category, state, identifiers, {'raw_line': line})
                    obs.append(ob)
                except:
                    pass

    # Look for resource_id mentions in free text
    # Find email addresses and resource IDs
    emails_in_text = set(re.findall(r'[\w.+\-]+@[\w.\-]+\.\w+', text))
    resource_ids_in_text = set(re.findall(r'(account_\d+|search_\d+|analytics_\d+|support_\d+|export_\d+|data_flow_\d+|backup_\d+|audit_record_\d+|tombstone_\d+|marketing_\d+)', text))

    # Store raw text for manual processing if needed
    if not obs and (resource_ids_in_text or emails_in_text):
        for rid in resource_ids_in_text:
            system_id, category = _infer_system_from_resource(rid, '', None)
            identifiers = {}
            # Try to associate with an email
            ob = _make_obs(file_id, captured_at, system_id, rid,
                           category, 'PRESENT', identifiers, {'pdf_text': text[:500]})
            obs.append(ob)

    return obs


# ─── PNG loader ──────────────────────────────────────────────────────────

def _load_png(path, file_id, captured_at):
    """Try to extract text from PNG using OCR or cached text."""
    cache_dir = os.path.join(os.path.dirname(__file__), 'cache')
    cache_file = os.path.join(cache_dir, f'{file_id}.txt')

    if os.path.exists(cache_file):
        with open(cache_file, encoding='utf-8') as f:
            text = f.read()
        return _parse_screenshot_text(text, file_id, captured_at)

    # Try tesseract
    try:
        import subprocess
        result = subprocess.run(['tesseract', path, 'stdout'],
                                capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and result.stdout.strip():
            text = result.stdout
            os.makedirs(cache_dir, exist_ok=True)
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(text)
            return _parse_screenshot_text(text, file_id, captured_at)
    except (FileNotFoundError, Exception):
        pass

    print(f"WARN: Cannot OCR PNG {file_id} ({path})", file=sys.stderr)
    return []


def _parse_screenshot_text(text, file_id, captured_at):
    """Parse OCR'd screenshot text for observations."""
    return _parse_pdf_text(text, file_id, captured_at)
