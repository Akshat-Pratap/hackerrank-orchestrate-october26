"""Evidence loaders — parse every evidence format into Observation dicts.

Observation fields:
  file_id, system_id, resource_id, category, state, captured_at,
  identifiers: {user_id, email, phone, email_hash, lookup_key},
  extra: {retention_until, tombstone_has_pii, enabled, restore_allowed, ...}
"""
import csv
import json
import os
import re
import sqlite3
import tempfile
from collections import defaultdict

# ── category inference ─────────────────────────────────────────────────────────
def _cat(system_id, resource_id, collection=None, extra_hint=None):
    rid = resource_id.lower()
    col = (collection or '').lower()
    hint = (extra_hint or '').lower()
    if col == 'security_audit_events' or rid.startswith('audit_record'):
        return 'SECURITY_AUDIT_LOG'
    if col == 'legal_hold' or rid.startswith('legal_hold'):
        return 'LEGAL_HOLD_RECORD'
    if col == 'backup_catalog' or rid.startswith('backup_'):
        return 'BACKUP_ARCHIVE'
    if col == 'connector_configurations' or rid.startswith('data_flow'):
        return 'DATA_FLOW'
    if col in ('customer_analytics_reports', 'analytics_profiles') or rid.startswith('analytics_'):
        return 'ANALYTICS_PROFILE'
    if col in ('support_conversations',) or rid.startswith('support_'):
        # If origin is attachment/PDF context, treat as SUPPORT_ATTACHMENT
        if 'attach' in hint or 'attachment' in col:
            return 'SUPPORT_ATTACHMENT'
        return 'SUPPORT_MESSAGE'
    if col in ('customer_search_documents',) or rid.startswith('search_'):
        return 'SEARCH_INDEX_ENTRY'
    if col in ('customer_export_jobs',) or rid.startswith('export_'):
        return 'USER_EXPORT'
    if col == 'tombstones' or rid.startswith('tombstone'):
        return 'ACCOUNT_TOMBSTONE'
    if col in ('customer_profiles', 'account_profiles') or rid.startswith('account_'):
        return 'USER_PROFILE'
    if rid.startswith('email_log_') or rid.startswith('email_delivery_'):
        return 'EMAIL_DELIVERY_LOG'
    if rid.startswith('cache_'):
        return 'CACHE_ENTRY'
    if rid.startswith('marketing_'):
        return 'MARKETING_PROFILE'
    return 'UNKNOWN'


def _ids(**kwargs):
    return {k: v for k, v in kwargs.items() if v}


# ── manifest ───────────────────────────────────────────────────────────────────
def load_evidence_manifest(path):
    with open(path, encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    return {r['file_id']: r for r in rows}


# ── main dispatcher ────────────────────────────────────────────────────────────
def load_all_evidence(manifest, dataset_root, cache_dir=None):
    """Return dict: file_id -> list[Observation]."""
    if cache_dir is None:
        cache_dir = os.path.join(os.path.dirname(__file__), 'cache')

    result = {}
    for file_id, entry in manifest.items():
        path = os.path.join(dataset_root, entry['file_path'])
        captured_at = entry['captured_at']
        origin = entry.get('origin', '')
        ext = os.path.splitext(path)[1].lower()
        try:
            if ext == '.sql':
                obs = _load_sql(file_id, path, captured_at)
            elif ext == '.json':
                obs = _load_json(file_id, path, captured_at, origin)
            elif ext == '.log':
                obs = _load_log(file_id, path, captured_at)
            elif ext == '.txt':
                obs = _load_txt(file_id, path, captured_at)
            elif ext in ('.pdf', '.png'):
                cache_path = os.path.join(cache_dir, file_id + '.txt')
                obs = _load_cache(file_id, cache_path, captured_at)
            else:
                obs = []
        except Exception as e:
            obs = []
            import sys
            print('WARN: load error %s: %s' % (file_id, e), file=sys.stderr)
        for ob in obs:
            ob['file_captured_at'] = captured_at
        result[file_id] = obs
    return result


# ── SQL loader ─────────────────────────────────────────────────────────────────
# ── SQL loader ─────────────────────────────────────────────────────────────────
_COLLECTION_MAPPING = {
    'customer_profiles': ('account_service', 'USER_PROFILE'),
    'customer_analytics_reports': ('analytics_platform', 'ANALYTICS_PROFILE'),
    'customer_search_documents': ('search_service', 'SEARCH_INDEX_ENTRY'),
    'support_conversations': ('support_platform', 'SUPPORT_MESSAGE'),
    'ticket_attachments': ('support_platform', 'SUPPORT_ATTACHMENT'),
    'connector_configurations': ('integration_service', 'DATA_FLOW'),
    'backup_catalog': ('backup_service', 'BACKUP_ARCHIVE'),
    'customer_export_jobs': ('export_service', 'USER_EXPORT'),
    'security_audit_events': ('security_service', 'SECURITY_AUDIT_LOG'),
    'deleted_customer_references': ('account_service', 'ACCOUNT_TOMBSTONE'),
    'retained_order_records': ('legal_service', 'LEGAL_HOLD_RECORD'),
}

_SYSTEM_FROM_TABLE = {
    'customer_profiles': ('account_service', 'USER_PROFILE'),
    'customer_profiles_primary': ('account_service', 'USER_PROFILE'),
    'customer_profiles_failover_replica': ('account_service', 'USER_PROFILE'),
    'customer_profiles_reporting_replica': ('account_service', 'USER_PROFILE'),
    'customer_profiles_regional_replica': ('account_service', 'USER_PROFILE'),
    'customer_search_documents': ('search_service', 'SEARCH_INDEX_ENTRY'),
    'search_documents_primary': ('search_service', 'SEARCH_INDEX_ENTRY'),
    'search_index_entries': ('search_service', 'SEARCH_INDEX_ENTRY'),
    'customer_analytics_profiles': ('analytics_platform', 'ANALYTICS_PROFILE'),
    'analytics_profiles': ('analytics_platform', 'ANALYTICS_PROFILE'),
    'support_records': ('support_platform', 'SUPPORT_MESSAGE'),
    'support_messages': ('support_platform', 'SUPPORT_MESSAGE'),
    'support_attachments': ('support_platform', 'SUPPORT_ATTACHMENT'),
    'customer_exports': ('export_service', 'USER_EXPORT'),
    'user_exports': ('export_service', 'USER_EXPORT'),
    'connector_subscriptions': ('integration_service', 'DATA_FLOW'),
    'backup_restore_entries': ('backup_service', 'BACKUP_ARCHIVE'),
    'security_audit_records': ('security_service', 'SECURITY_AUDIT_LOG'),
    'email_delivery_logs': ('notification_service', 'EMAIL_DELIVERY_LOG'),
    'tombstones': ('account_service', 'ACCOUNT_TOMBSTONE'),
    'cache_entries': ('cache_service', 'CACHE_ENTRY'),
    'marketing_profiles': ('marketing_service', 'MARKETING_PROFILE'),
}

def _load_sql(file_id, path, captured_at):
    with open(path, encoding='utf-8', errors='replace') as f:
        sql = f.read()

    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(sql)
    except Exception:
        pass

    obs = []
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cur.fetchall()]

    has_customer_data_primary = 'customer_data_primary' in tables
    primary_rids = set()
    if has_customer_data_primary:
        try:
            cur.execute("SELECT resource_id FROM customer_data_primary")
            primary_rids = {r[0] for r in cur.fetchall()}
        except Exception:
            pass

    for table in tables:
        if table == 'snapshot_scope':
            continue

        if table.startswith('customer_data_'):
            is_primary = (table == 'customer_data_primary')
            is_replica = not is_primary
            try:
                cur.execute('SELECT * FROM %s' % table)
                cols = [d[0] for d in cur.description]
                for row in cur.fetchall():
                    rec = dict(zip(cols, row))
                    rid = rec.get('resource_id', '')
                    if not rid:
                        continue
                    sys_id = rec.get('origin_system', '')
                    coll = rec.get('collection_name', '')
                    if coll in _COLLECTION_MAPPING:
                        def_sys, cat = _COLLECTION_MAPPING[coll]
                        if not sys_id:
                            sys_id = def_sys
                    else:
                        cat = 'UNKNOWN'

                    rj_str = rec.get('record_json', '')
                    try:
                        rj = json.loads(rj_str) if isinstance(rj_str, str) else (rj_str or {})
                    except Exception:
                        rj = {}

                    doc = rj.get('document') if isinstance(rj.get('document'), dict) else {}
                    uid = (rj.get('user_id') or rj.get('customer_reference') or 
                           rj.get('subject_reference') or doc.get('customer_reference') or 
                           doc.get('user_id'))
                    sel = rj.get('subject_selector')
                    if sel:
                        if '@' in sel:
                            pass
                        elif sel.startswith('user_'):
                            if not uid:
                                uid = sel

                    email = (rj.get('email') or rj.get('owner_email') or 
                             rj.get('requester_email') or doc.get('email') or 
                             (sel if sel and '@' in sel else None))
                    phone = (rj.get('phone') or rj.get('owner_phone') or 
                             rj.get('requester_phone') or doc.get('phone'))
                    email_hash = rj.get('email_hash') or doc.get('email_hash')

                    if not email and rj.get('message_text'):
                        m = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', rj['message_text'])
                        if m:
                            email = m.group(0)

                    if cat in ('USER_PROFILE', 'SEARCH_INDEX_ENTRY', 'USER_EXPORT', 'SUPPORT_ATTACHMENT', 'LEGAL_HOLD_RECORD', 'SECURITY_AUDIT_LOG'):
                        state = 'PRESENT'
                    elif cat == 'ANALYTICS_PROFILE':
                        has_pii = bool(uid or email or phone or email_hash)
                        state = 'PRESENT' if has_pii else 'ANONYMIZED'
                    elif cat == 'SUPPORT_MESSAGE':
                        txt = rj.get('message_text', '')
                        state = 'REDACTED' if '[REDACTED]' in txt else 'PRESENT'
                    elif cat == 'DATA_FLOW':
                        state = 'ACTIVE' if rj.get('enabled', True) else 'DISABLED'
                    elif cat == 'BACKUP_ARCHIVE':
                        state = 'ACTIVE' if rj.get('restore_allowed', True) else 'BLOCKED'
                    elif cat == 'ACCOUNT_TOMBSTONE':
                        has_pii = bool(email or phone or rj.get('full_name') or rj.get('name'))
                        state = 'PRESENT' if has_pii else 'REDACTED'
                    else:
                        state = 'PRESENT'

                    drift = bool(is_replica and has_customer_data_primary and rid not in primary_rids)

                    ob = {
                        'file_id': file_id,
                        'system_id': sys_id,
                        'resource_id': rid,
                        'category': cat,
                        'state': state,
                        'captured_at': captured_at,
                        'identifiers': _ids(
                            user_id=uid,
                            email=email,
                            phone=phone,
                            email_hash=email_hash,
                        ),
                        'extra': {
                            'table': table,
                            'is_primary': is_primary,
                            'is_replica': is_replica,
                            'replication_drift': drift,
                            'tombstone_has_pii': bool(email or phone or email_hash) if cat == 'ACCOUNT_TOMBSTONE' else False,
                        }
                    }
                    obs.append(ob)
            except Exception:
                pass
        else:
            sys_id, cat = _SYSTEM_FROM_TABLE.get(table, ('unknown_service', 'UNKNOWN'))
            try:
                cur.execute('SELECT * FROM %s' % table)
                cols = [d[0] for d in cur.description]
                for row in cur.fetchall():
                    rec = dict(zip(cols, row))
                    rid = rec.get('resource_id') or rec.get('id') or rec.get('user_id', '')
                    if not rid:
                        continue

                    uid = rec.get('user_id') or rec.get('customer_reference') or rec.get('subject_reference')
                    email = (rec.get('email') or rec.get('customer_email') or rec.get('owner_email') or rec.get('requester_email') or '')
                    phone = rec.get('phone') or rec.get('owner_phone') or rec.get('requester_phone')
                    email_hash = rec.get('email_hash')
                    lookup_key = rec.get('source_resource_id') or rec.get('lookup_key')

                    state = 'PRESENT'
                    if rec.get('deleted_at') or rec.get('is_deleted') or rec.get('account_status') == 'DELETED':
                        state = 'ABSENT'
                    elif rec.get('anonymized_at') or rec.get('is_anonymized'):
                        state = 'ANONYMIZED'
                    elif rec.get('redacted_at') or rec.get('is_redacted'):
                        state = 'REDACTED'
                    elif cat == 'ANALYTICS_PROFILE':
                        has_pii = bool(uid or email or phone or email_hash)
                        state = 'PRESENT' if has_pii else 'ANONYMIZED'
                    elif cat == 'SUPPORT_MESSAGE':
                        state = 'REDACTED' if '[REDACTED]' in (rec.get('message_excerpt') or '') else 'PRESENT'
                    elif cat == 'DATA_FLOW':
                        state = 'ACTIVE' if rec.get('enabled') in (1, '1', True, 'true', 'TRUE') else 'DISABLED'
                    elif cat == 'BACKUP_ARCHIVE':
                        state = 'ACTIVE' if rec.get('restore_allowed') in (1, '1', True, 'true', 'TRUE') else 'BLOCKED'
                    elif cat == 'ACCOUNT_TOMBSTONE':
                        has_pii = bool(email or phone or rec.get('full_name') or rec.get('name'))
                        state = 'PRESENT' if has_pii else 'REDACTED'

                    ob = {
                        'file_id': file_id,
                        'system_id': sys_id,
                        'resource_id': rid,
                        'category': cat,
                        'state': state,
                        'captured_at': captured_at,
                        'identifiers': _ids(
                            user_id=uid,
                            email=email,
                            phone=phone,
                            email_hash=email_hash,
                            lookup_key=lookup_key,
                        ),
                        'extra': {
                            'table': table,
                            'retention_until': rec.get('retention_until'),
                            'tombstone_has_pii': (cat == 'ACCOUNT_TOMBSTONE' and state == 'PRESENT'),
                            'replica': table,
                        }
                    }
                    obs.append(ob)
            except Exception:
                pass

    conn.close()
    return obs


# ── JSON loader ────────────────────────────────────────────────────────────────
def _load_json(file_id, path, file_captured_at, origin):
    with open(path, encoding='utf-8') as f:
        data = json.load(f)

    if 'snapshots' in data:
        return _parse_snapshot_bundle(file_id, data, file_captured_at)
    elif 'service_exports' in data:
        return _parse_service_export(file_id, data, file_captured_at)
    elif isinstance(data, list):
        return _parse_json_list(file_id, data, file_captured_at)
    elif isinstance(data, dict):
        return _parse_json_dict(file_id, data, file_captured_at)
    return []


def _parse_snapshot_bundle(file_id, data, file_captured_at):
    """Parse snapshot bundles — use inner snapshot captured_at."""
    obs = []
    for snap in data.get('snapshots', []):
        snap_captured_at = snap.get('captured_at', file_captured_at)
        collection = snap.get('collection', '')
        data_store = snap.get('data_store', '')

        for rec in snap.get('records', []):
            rid = rec.get('resource_id', '')
            if not rid:
                continue

            # Derive system_id from data_store/collection
            sys_id = _system_from_collection(data_store, collection)
            cat = _cat(sys_id, rid, collection)

            # State
            state = _state_from_record(rec, collection)

            # Identifiers
            uid = (rec.get('customer_reference') or rec.get('user_id') or
                   rec.get('subject_reference'))
            email = (rec.get('email') or
                     (rec.get('document', {}) or {}).get('email') or
                     rec.get('owner_email'))
            if email:
                email = email.lower()
            phone = rec.get('phone')
            ehash = (rec.get('email_hash') or
                     (rec.get('document', {}) or {}).get('email_hash'))
            lookup_key = (rec.get('lookup_key') or
                          (rec.get('document', {}) or {}).get('display_name'))

            extra = {
                'collection': collection,
                'retention_until': rec.get('retention_until'),
                'restore_allowed': rec.get('restore_allowed'),
                'enabled': rec.get('enabled'),
                'tombstone_has_pii': bool(rec.get('email') or rec.get('full_name') or rec.get('phone'))
                    if 'tombstone' in collection else False,
            }

            obs.append({
                'file_id': file_id,
                'system_id': sys_id,
                'resource_id': rid,
                'category': cat,
                'state': state,
                'captured_at': snap_captured_at,
                'identifiers': _ids(
                    user_id=uid,
                    email=email,
                    phone=phone,
                    email_hash=ehash,
                    lookup_key=lookup_key,
                ),
                'extra': extra,
            })

    return obs


def _parse_service_export(file_id, data, file_captured_at):
    """Parse service_resource_export JSON (evidence_92, evidence_94, etc.)."""
    obs = []
    exports = data.get('service_exports', {})

    for svc, svc_data in exports.items():
        if not isinstance(svc_data, dict):
            continue
        for coll, records in svc_data.items():
            if not isinstance(records, list):
                continue
            for rec in records:
                rid = rec.get('resource_id', '')
                if not rid:
                    continue

                observed_at = rec.get('observed_at', file_captured_at)
                cat = _cat(svc, rid, coll)

                # State per section
                state = _state_from_service_export_rec(rec, coll)

                # Identifiers
                uid = (rec.get('customer_reference') or rec.get('subject_reference')
                       or rec.get('user_id'))
                email = rec.get('email') or rec.get('customer_email') or rec.get('owner_email') or rec.get('requester_email')
                if not email and rec.get('query') and '@' in rec.get('query', ''):
                    email = rec.get('query')
                if email:
                    email = email.lower()
                # Search hits
                hits_docs = (rec.get('hits', {}) or {}).get('documents', []) or []
                if not email and hits_docs:
                    email = (hits_docs[0].get('email') or '').lower() or None
                    if not uid:
                        uid = hits_docs[0].get('customer_reference')
                phone = rec.get('phone') or rec.get('owner_phone') or rec.get('requester_phone')
                ehash = rec.get('email_hash')

                obs.append({
                    'file_id': file_id,
                    'system_id': svc,
                    'resource_id': rid,
                    'category': cat,
                    'state': state,
                    'captured_at': observed_at,
                    'identifiers': _ids(user_id=uid, email=email, phone=phone, email_hash=ehash),
                    'extra': {
                        'restore_allowed': rec.get('restore_allowed'),
                        'enabled': rec.get('enabled'),
                        'status_code': rec.get('status_code'),
                        'retention_until': rec.get('retention_until'),
                    },
                })

    return obs


def _parse_json_list(file_id, data, captured_at):
    obs = []
    for rec in data:
        if not isinstance(rec, dict):
            continue
        rid = rec.get('resource_id') or rec.get('id', '')
        if not rid:
            continue
        sys_id = rec.get('system_id', 'unknown_service')
        cat = _cat(sys_id, rid)
        state = _state_from_record(rec, '')
        uid = rec.get('user_id') or rec.get('customer_reference')
        email = (rec.get('email') or '').lower() or None
        obs.append({
            'file_id': file_id, 'system_id': sys_id,
            'resource_id': rid, 'category': cat,
            'state': state, 'captured_at': captured_at,
            'identifiers': _ids(user_id=uid, email=email),
            'extra': {},
        })
    return obs


def _parse_json_dict(file_id, data, captured_at):
    """Fallback: flatten a generic dict, handling export jobs and audit ledgers."""
    obs = []
    top_source = data.get('source') or data.get('origin') or ''
    top_coll = data.get('collection', '')
    top_captured = data.get('captured_at') or data.get('exported_at') or captured_at

    for key, val in data.items():
        if isinstance(val, list):
            for rec in val:
                if isinstance(rec, dict) and rec.get('resource_id'):
                    rid = rec['resource_id']
                    rec_sys = rec.get('system') or rec.get('system_id')
                    if rec_sys:
                        sys_id = rec_sys
                    elif 'export' in top_coll or 'export' in top_source or rid.startswith('export_'):
                        sys_id = 'export_service'
                    elif 'audit' in top_source or rid.startswith('audit_'):
                        sys_id = 'security_service'
                    elif key in ('records', 'items', 'entries'):
                        sys_id = _system_from_resource_id(rid)
                    else:
                        sys_id = key

                    rec_type = rec.get('record_type')
                    if rec_type:
                        cat = rec_type
                    elif 'export' in top_coll or rid.startswith('export_'):
                        cat = 'USER_EXPORT'
                    else:
                        cat = _cat(sys_id, rid, top_coll)

                    uid = rec.get('user_id') or rec.get('customer_reference')
                    email = (rec.get('email') or rec.get('owner_email') or rec.get('customer_email') or rec.get('requester_email') or '').lower() or None
                    phone = rec.get('phone') or rec.get('owner_phone') or rec.get('requester_phone')
                    ehash = rec.get('email_hash')

                    subj = rec.get('subject_reference')
                    if subj:
                        if '@' in subj:
                            email = subj.lower()
                        elif subj.startswith('user_'):
                            uid = subj

                    if 'download_available' in rec:
                        state = 'PRESENT' if rec['download_available'] else 'ABSENT'
                    elif rec.get('result') == 'FOUND':
                        state = 'PRESENT'
                    elif rec.get('result') == 'DELETED':
                        state = 'ABSENT'
                    else:
                        state = _state_from_record(rec, top_coll or key)

                    rec_time = rec.get('recorded_at') or rec.get('created_at') or top_captured

                    obs.append({
                        'file_id': file_id,
                        'system_id': sys_id,
                        'resource_id': rid,
                        'category': cat,
                        'state': state,
                        'captured_at': rec_time,
                        'identifiers': _ids(user_id=uid, email=email, phone=phone, email_hash=ehash),
                        'extra': {
                            'restore_allowed': rec.get('restore_allowed'),
                            'enabled': rec.get('enabled'),
                            'retention_until': rec.get('retention_until'),
                        },
                    })
    return obs


# ── LOG loader ─────────────────────────────────────────────────────────────────
_LOG_RESOURCE_RE = re.compile(r'resource_id=([\w\-]+)')
_LOG_SYS_RE = re.compile(r'service=([\w\-]+)')
_LOG_TRACE_RE = re.compile(r'trace_id=([\w\-]+)')
_LOG_EMAIL_RE = re.compile(r'[\w.+\-]+@[\w.\-]+\.\w+')
_LOG_USER_RE = re.compile(r'\b(user_\d+)\b')
_LOG_HASH_RE = re.compile(r'\b([a-fA-F0-9]{64})\b')
_LOG_STATUS_RE = re.compile(r'(?:http_status|status|result)=(\w+)')
_LOG_TIME_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)')


def _load_log(file_id, path, captured_at):
    obs = []
    traces = defaultdict(lambda: {
        'identifiers': {},
        'events': [],
        'lines': [],
    })
    standalone = []

    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            t_m = _LOG_TIME_RE.match(line)
            l_time = t_m.group(1) if t_m else captured_at

            json_obj = None
            if '{' in line and '}' in line:
                try:
                    s_idx = line.index('{')
                    e_idx = line.rindex('}')
                    json_obj = json.loads(line[s_idx:e_idx+1])
                except Exception:
                    pass

            if json_obj:
                l_time = json_obj.get('timestamp') or json_obj.get('time') or l_time
                tr_id = json_obj.get('trace_id')
                rid = json_obj.get('resource_id') or json_obj.get('entity_id') or json_obj.get('account_id')
                sys_id = json_obj.get('service') or json_obj.get('logger') or json_obj.get('system')
                email = (json_obj.get('email') or json_obj.get('customer_email') or
                         json_obj.get('requester_email') or json_obj.get('subject_key') or
                         json_obj.get('lookup_key'))
                if email and '@' in email:
                    email = email.lower()
                else:
                    email = None
                uid = json_obj.get('user_id') or json_obj.get('customer_reference') or json_obj.get('subject_ref') or json_obj.get('subject_reference')
                ehash = json_obj.get('correlation_key') or json_obj.get('email_hash')
                phone = json_obj.get('phone') or json_obj.get('requester_phone')

                status_code = str(json_obj.get('http_status') or json_obj.get('status') or json_obj.get('result') or '').upper()
                rows = str(json_obj.get('rows', ''))
                event = json_obj.get('event', '')

                state = 'PRESENT'
                if status_code in ('404', 'NOT_FOUND', 'DELETED', 'ABSENT') or rows == '0':
                    state = 'ABSENT'
                elif json_obj.get('deletion_block') is False or json_obj.get('restore_allowed') is True:
                    state = 'ACTIVE'
                elif json_obj.get('deletion_block') is True or json_obj.get('restore_allowed') is False:
                    state = 'BLOCKED'
                elif json_obj.get('enabled') is True:
                    state = 'ACTIVE'
                elif json_obj.get('enabled') is False:
                    state = 'DISABLED'
                elif rows == '1' or status_code in ('200', 'FOUND', 'HIT') or event in ('audit_record_read_completed', 'profile_lookup_completed'):
                    state = 'PRESENT'
            else:
                tr_m = _LOG_TRACE_RE.search(line)
                tr_id = tr_m.group(1) if tr_m else None

                matches = re.findall(r'(\w+)=(?:"([^"]*)"|([^\s"]+))', line)
                kv = {m[0]: m[1] if m[1] != '' else m[2] for m in matches} if matches else {}

                tr_id = kv.get('trace_id', tr_id)
                rid = kv.get('resource_id', kv.get('entity_id', kv.get('account_id')))
                if not rid:
                    rid_m = _LOG_RESOURCE_RE.search(line)
                    rid = rid_m.group(1).rstrip('.,;') if rid_m else None

                sys_id = kv.get('service', kv.get('system'))
                if not sys_id:
                    sys_m = _LOG_SYS_RE.search(line)
                    sys_id = sys_m.group(1) if sys_m else None

                subj = kv.get('subject_reference', kv.get('customer_reference', kv.get('subject_ref', '')))
                lkey = kv.get('lookup_key', kv.get('query', ''))
                email = None
                if '@' in lkey:
                    email = lkey.lower()
                elif '@' in subj:
                    email = subj.lower()
                else:
                    em_m = _LOG_EMAIL_RE.search(line)
                    email = em_m.group(0).lower() if em_m else None

                uid = None
                if subj and subj.startswith('user_'):
                    uid = subj
                else:
                    u_m = _LOG_USER_RE.search(line)
                    uid = u_m.group(1) if u_m else None

                ehash = kv.get('correlation_key', kv.get('email_hash'))
                if not ehash or len(ehash) != 64:
                    h_m = _LOG_HASH_RE.search(line)
                    ehash = h_m.group(1) if h_m else None

                phone = kv.get('phone', kv.get('requester_phone'))
                status_code = str(kv.get('result', kv.get('status', kv.get('http_status', '')))).upper()
                rows = str(kv.get('rows', ''))
                marker_found = kv.get('marker_found')

                state = 'PRESENT'
                if status_code in ('404', 'NOT_FOUND', 'DELETED', 'ABSENT') or rows == '0':
                    state = 'ABSENT'
                elif marker_found == 'false':
                    state = 'PRESENT'
                elif kv.get('deletion_block') == 'false' or kv.get('restore_allowed') == 'true' or 'eligible=true deletion_block=false' in line:
                    state = 'ACTIVE'
                elif kv.get('deletion_block') == 'true' or kv.get('restore_allowed') == 'false':
                    state = 'BLOCKED'
                elif kv.get('enabled') == 'true' or 'remains enabled' in line or 'enabled=true' in line:
                    state = 'ACTIVE'
                elif kv.get('enabled') == 'false':
                    state = 'DISABLED'
                elif rows == '1' or status_code in ('200', 'FOUND', 'HIT') or 'result=hit' in line or 'matched_value' in line:
                    state = 'PRESENT'

            s_id = _system_from_resource_id(rid) if rid and _system_from_resource_id(rid) != 'unknown_service' else (sys_id or 'unknown_service')
            cat = None
            if 'email_opt_in' in line:
                cat = 'MARKETING_PROFILE'
            elif 'marker_found' in line or 'support_replica' in line or 'support_replica' in path or 'legacy_contact_index' in line:
                cat = 'SECONDARY_IDENTIFIER'

            if tr_id:
                traces[tr_id]['lines'].append(line)
                if email and not traces[tr_id]['identifiers'].get('email'):
                    traces[tr_id]['identifiers']['email'] = email
                if uid and not traces[tr_id]['identifiers'].get('user_id'):
                    traces[tr_id]['identifiers']['user_id'] = uid
                if ehash and not traces[tr_id]['identifiers'].get('email_hash'):
                    traces[tr_id]['identifiers']['email_hash'] = ehash
                if phone and not traces[tr_id]['identifiers'].get('phone'):
                    traces[tr_id]['identifiers']['phone'] = phone
                if rid:
                    traces[tr_id]['events'].append({
                        'resource_id': rid,
                        'system_id': s_id,
                        'state': state,
                        'time': l_time,
                        'category': cat,
                    })
            elif rid:
                standalone.append({
                    'file_id': file_id,
                    'system_id': s_id,
                    'resource_id': rid,
                    'category': cat or _cat(s_id, rid),
                    'state': state,
                    'captured_at': l_time,
                    'identifiers': _ids(user_id=uid, email=email, phone=phone, email_hash=ehash, lookup_key=email),
                    'extra': {},
                })

    # Convert trace events into observations
    seen = {}
    for tr_id, tr_data in traces.items():
        ids = tr_data['identifiers']
        for ev in tr_data['events']:
            rid = ev['resource_id']
            sys_id = ev['system_id']
            key = (sys_id, rid)
            cat = ev.get('category') or _cat(sys_id, rid)
            ob = {
                'file_id': file_id,
                'system_id': sys_id,
                'resource_id': rid,
                'category': cat,
                'state': ev['state'],
                'captured_at': ev['time'],
                'identifiers': _ids(
                    user_id=ids.get('user_id'),
                    email=ids.get('email'),
                    phone=ids.get('phone'),
                    email_hash=ids.get('email_hash'),
                    lookup_key=ids.get('email'),
                ),
                'extra': {},
            }
            if key not in seen:
                seen[key] = ob
                obs.append(ob)
            else:
                cur = seen[key]
                if ids.get('email') and not cur['identifiers'].get('email'):
                    cur['identifiers']['email'] = ids.get('email')
                if ids.get('user_id') and not cur['identifiers'].get('user_id'):
                    cur['identifiers']['user_id'] = ids.get('user_id')
                if ids.get('phone') and not cur['identifiers'].get('phone'):
                    cur['identifiers']['phone'] = ids.get('phone')
                if ids.get('email_hash') and not cur['identifiers'].get('email_hash'):
                    cur['identifiers']['email_hash'] = ids.get('email_hash')
                if ev['state'] in ('ABSENT', 'ACTIVE'):
                    cur['state'] = ev['state']

    obs.extend(standalone)
    return obs


# ── TXT loader ─────────────────────────────────────────────────────────────────
# Handover pipe format: timestamp | system | resource_id | category | status | identifier
_PIPE_RE = re.compile(
    r'(\d{4}-\d{2}-\d{2}T[\d:.]+Z?)\s*\|\s*([\w_]+)\s*\|\s*([\w_]+)\s*\|\s*([\w_]+)\s*\|\s*([\w_]+)\s*\|\s*(.+)'
)
# Status -> state mapping for handover files
_HANDOVER_STATUS_MAP = {
    'NOT_FOUND': 'ABSENT', 'ABSENT': 'ABSENT',
    'FOUND': 'PRESENT', 'ACTIVE': 'ACTIVE',
    'ANONYMIZED': 'ANONYMIZED', 'REDACTED': 'REDACTED',
    'IDENTIFIABLE': 'PRESENT', 'BLOCKED': 'BLOCKED', 'DISABLED': 'DISABLED',
}


def _load_txt(file_id, path, captured_at):
    obs = []
    with open(path, encoding='utf-8', errors='replace') as f:
        content = f.read()

    # Try structured pipe format first
    pipe_found = False
    for line in content.splitlines():
        line = line.strip()
        m = _PIPE_RE.match(line.lstrip('- '))
        if m:
            pipe_found = True
            ts, sys_id, rid, cat_raw, status_raw, identifier = (
                m.group(1), m.group(2), m.group(3), m.group(4),
                m.group(5).strip(), m.group(6).strip()
            )
            # Use explicit category from file if known
            state = _HANDOVER_STATUS_MAP.get(status_raw.upper(), 'PRESENT')
            cat = cat_raw  # Use the explicit category from handover file

            # Parse identifier: email or user_id
            email_m = re.search(r'([\w.+\-]+@[\w.\-]+\.\w+)', identifier)
            user_m = re.search(r'user_\d+', identifier)
            email = email_m.group(1).lower() if email_m else None
            uid = user_m.group(0) if user_m else None

            # For DATA_FLOW category, ACTIVE = PRESENT in terms of finding
            if cat == 'DATA_FLOW' and state == 'ACTIVE':
                state = 'ACTIVE'  # keep ACTIVE for data flows
            elif cat == 'BACKUP_ARCHIVE' and state == 'ACTIVE':
                state = 'ACTIVE'  # unblocked backup

            obs.append({
                'file_id': file_id,
                'system_id': sys_id,
                'resource_id': rid,
                'category': cat,
                'state': state,
                'captured_at': ts,
                'identifiers': _ids(user_id=uid, email=email),
                'extra': {},
            })

    if pipe_found:
        return obs

    # Fallback: simple resource_id: state lines
    for line in content.splitlines():
        line = line.strip()
        m = re.match(r'([\w_]+)/([\w_]+)\s*:\s*(\w+)', line)
        if m:
            sys_id, rid, state = m.group(1), m.group(2), m.group(3).upper()
            cat = _cat(sys_id, rid)
            email_m = re.search(r'([\w.+\-]+@[\w.\-]+\.\w+)', line)
            user_m = re.search(r'user_\d+', line)
            email = email_m.group(1).lower() if email_m else None
            uid = user_m.group(0) if user_m else None
            obs.append({
                'file_id': file_id, 'system_id': sys_id,
                'resource_id': rid, 'category': cat,
                'state': state, 'captured_at': captured_at,
                'identifiers': _ids(user_id=uid, email=email),
                'extra': {},
            })
    return obs


# ── CACHE (PDF/PNG text) loader ────────────────────────────────────────────────
def _load_cache(file_id, cache_path, captured_at):
    if not os.path.exists(cache_path):
        return []

    with open(cache_path, encoding='utf-8') as f:
        text = f.read()

    obs = []

    # Structured key=value format (our PNG caches)
    if 'system_id=' in text and 'resource_id=' in text:
        return _parse_structured_cache(file_id, text, captured_at)

    # Raw PDF text — extract resource IDs and identifiers
    resource_ids = set(re.findall(r'(?:account|search|analytics|support|export|data_flow|backup|audit_record|tombstone|marketing|email_delivery|cache)_\d+', text))
    users = set(re.findall(r'user_\d+', text))
    emails = set(re.findall(r'[\w.+\-]+@[\w.\-]+\.\w+', text))

    uid = next(iter(users), None)
    email = next(iter(emails), None)

    for rid in resource_ids:
        sys_id = _system_from_resource_id(rid)
        cat = _cat(sys_id, rid)
        obs.append({
            'file_id': file_id, 'system_id': sys_id,
            'resource_id': rid, 'category': cat,
            'state': 'PRESENT', 'captured_at': captured_at,
            'identifiers': _ids(user_id=uid, email=email.lower() if email else None),
            'extra': {},
        })

    return obs


def _parse_structured_cache(file_id, text, captured_at):
    """Parse structured key=value cache files (our hand-written PNG caches)."""
    obs = []
    # Collect all numbered resource blocks
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    kv = {}
    for l in lines:
        if '=' in l:
            k, _, v = l.partition('=')
            kv[k.strip()] = v.strip()

    # Find all resource_id_N entries
    base_rid = kv.get('resource_id')
    base_sys = kv.get('system_id', 'unknown_service')
    base_email = (kv.get('email') or '').lower() or None
    base_uid = kv.get('user_id')
    base_state = kv.get('state', 'PRESENT').upper()

    if base_rid:
        # Allow explicit category override in cache file
        explicit_cat = kv.get('category')
        extra_hint = kv.get('extra_hint', '')
        cat = explicit_cat or _cat(base_sys, base_rid, extra_hint=extra_hint)
        obs.append({
            'file_id': file_id, 'system_id': base_sys,
            'resource_id': base_rid, 'category': cat,
            'state': base_state, 'captured_at': captured_at,
            'identifiers': _ids(user_id=base_uid, email=base_email),
            'extra': {'tombstone_has_pii': bool(base_email or kv.get('phone') or kv.get('name')) if 'tombstone' in base_rid else False},
        })

    # Numbered variants: resource_id_2, resource_id_3...
    i = 2
    while True:
        rid_key = 'resource_id_%d' % i
        if rid_key not in kv:
            break
        rid = kv[rid_key]
        email = (kv.get('email_%d' % i) or '').lower() or None
        uid = kv.get('user_id_%d' % i)
        state = kv.get('state_%d' % i, 'PRESENT').upper()
        cat = _cat(base_sys, rid)
        obs.append({
            'file_id': file_id, 'system_id': base_sys,
            'resource_id': rid, 'category': cat,
            'state': state, 'captured_at': captured_at,
            'identifiers': _ids(user_id=uid, email=email),
            'extra': {},
        })
        i += 1

    return obs


# ── helpers ────────────────────────────────────────────────────────────────────
def _system_from_collection(data_store, collection):
    ds = data_store.lower()
    col = collection.lower()
    if 'account' in ds or 'customer_profiles' in col:
        return 'account_service'
    if 'search' in ds or 'search' in col:
        return 'search_service'
    if 'analytics' in ds or 'analytics' in col:
        return 'analytics_platform'
    if 'support' in ds or 'support' in col:
        return 'support_platform'
    if 'backup' in ds or 'backup' in col:
        return 'backup_service'
    if 'export' in ds or 'export' in col:
        return 'export_service'
    if 'connector' in ds or 'connector' in col:
        return 'integration_service'
    if 'security' in ds or 'security' in col or 'audit' in col:
        return 'security_service'
    if 'tombstone' in ds or 'tombstone' in col:
        return 'account_service'
    if 'legal' in col:
        return 'legal_service'
    return data_store or 'unknown_service'


def _system_from_resource_id(rid):
    if rid.startswith('account_') or rid.startswith('tombstone_'):
        return 'account_service'
    if rid.startswith('search_'):
        return 'search_service'
    if rid.startswith('analytics_'):
        return 'analytics_platform'
    if rid.startswith('support_'):
        return 'support_platform'
    if rid.startswith('backup_'):
        return 'backup_service'
    if rid.startswith('export_'):
        return 'export_service'
    if rid.startswith('data_flow_'):
        return 'integration_service'
    if rid.startswith('audit_record_'):
        return 'security_service'
    if rid.startswith('email_delivery_') or rid.startswith('email_log_'):
        return 'notification_service'
    if rid.startswith('cache_'):
        return 'cache_service'
    if rid.startswith('marketing_'):
        return 'marketing_service'
    return 'unknown_service'


def _state_from_record(rec, collection):
    if rec.get('deleted_at') or rec.get('is_deleted') is True:
        return 'ABSENT'
    if rec.get('anonymized_at') or rec.get('is_anonymized') is True:
        return 'ANONYMIZED'
    if rec.get('redacted_at') or rec.get('is_redacted') is True:
        return 'REDACTED'
    msg = (rec.get('message_text') or '')
    if msg == '[REDACTED]':
        return 'REDACTED'
    return 'PRESENT'


def _state_from_service_export_rec(rec, collection):
    """Determine state from service_resource_export record."""
    sc = rec.get('status_code')
    if sc == 404:
        return 'ABSENT'

    # Search index
    if 'search' in collection.lower() or 'hits' in rec:
        hits = rec.get('hits')
        if isinstance(hits, dict):
            if hits.get('total', 0) == 0:
                return 'ABSENT'
            return 'PRESENT'

    # Analytics: null identifiers = anonymized
    if 'analytic' in collection.lower():
        has_pii = bool(rec.get('email') or rec.get('customer_reference') or rec.get('email_hash') or rec.get('phone'))
        if not has_pii:
            return 'ANONYMIZED'
        return 'PRESENT'

    # Support: check message
    msg = rec.get('message_excerpt') or rec.get('message_text') or ''
    if msg == '[REDACTED]' or rec.get('is_redacted'):
        return 'REDACTED'

    # Connectors: enabled=False means disabled
    if 'connector' in collection.lower() or rec.get('enabled') is not None:
        enabled = rec.get('enabled')
        if enabled is False:
            return 'DISABLED'
        if enabled is True:
            return 'ACTIVE'

    # Backup: restore_allowed=False means blocked
    if 'backup' in collection.lower() or rec.get('restore_allowed') is not None:
        ra = rec.get('restore_allowed')
        if ra is False:
            return 'BLOCKED'
        if ra is True:
            return 'ACTIVE'

    return 'PRESENT'
