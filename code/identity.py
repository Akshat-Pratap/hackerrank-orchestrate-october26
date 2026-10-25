"""Identity resolver: maps emails to user_ids and collects all identifiers."""
import re
from collections import defaultdict


def _normalize_email(e):
    if e is None:
        return None
    return e.strip().lower()


def _normalize_phone(p):
    if p is None:
        return None
    return re.sub(r'[^0-9+]', '', p)


def build_identity_index(user_identities, user_audit_log, system_activity):
    """Return an IdentityIndex object.

    Provides:
      - resolve_email(email) -> user_id or None
      - get_identifiers(user_id) -> {emails, phones, email_hashes, user_id, account_id}
      - resolve_account(account_id) -> user_id
    """
    idx = IdentityIndex()

    # Current identities
    for u in user_identities:
        uid = u['user_id']
        email = _normalize_email(u.get('email'))
        phone = _normalize_phone(u.get('phone'))
        ehash = u.get('email_hash', '').strip() or None

        idx._user_to_ids[uid]['emails'].add(email)
        if phone:
            idx._user_to_ids[uid]['phones'].add(phone)
        if ehash:
            idx._user_to_ids[uid]['email_hashes'].add(ehash)
        idx._user_to_ids[uid]['user_id'] = uid
        idx._user_to_ids[uid]['name'] = u.get('name', '')
        if email:
            idx._email_to_user[email] = uid

    # Historical identities from audit log
    for entry in user_audit_log:
        uid = entry['user_id']
        field = entry['field_name']
        old_val = entry.get('old_value', '').strip()
        new_val = entry.get('new_value', '').strip()

        if field == 'email':
            if old_val:
                ne = _normalize_email(old_val)
                idx._user_to_ids[uid]['emails'].add(ne)
                idx._email_to_user[ne] = uid
            if new_val:
                ne = _normalize_email(new_val)
                idx._user_to_ids[uid]['emails'].add(ne)
                idx._email_to_user[ne] = uid
        elif field == 'phone':
            if old_val:
                idx._user_to_ids[uid]['phones'].add(_normalize_phone(old_val))
            if new_val:
                idx._user_to_ids[uid]['phones'].add(_normalize_phone(new_val))
        elif field == 'email_hash':
            if old_val:
                idx._user_to_ids[uid]['email_hashes'].add(old_val)
            if new_val:
                idx._user_to_ids[uid]['email_hashes'].add(new_val)

    # LINK_RESOURCE_IDENTITY events
    for act in system_activity:
        if act['event_type'] == 'LINK_RESOURCE_IDENTITY':
            details = act['details']
            resource_id = act['resource_id']
            # Parse user_id and email from details
            m_user = re.search(r'user_(\d+)', details)
            m_email = re.search(r'to\s+([\w.+\-]+@[\w.\-]+)\s+and', details)
            if m_user:
                uid = f'user_{m_user.group(1)}'
                idx._resource_to_user[resource_id] = uid
                if m_email:
                    email = _normalize_email(m_email.group(1))
                    idx._user_to_ids[uid]['emails'].add(email)
                    idx._email_to_user[email] = uid

    # Build account_id -> user_id mapping from user_identities
    # Account IDs follow pattern account_XXX where XXX matches user number
    # But we also need to build this from evidence later
    for u in user_identities:
        uid = u['user_id']
        # Extract user number
        num = uid.replace('user_', '')
        acct = f'account_{num}'
        idx._account_to_user[acct] = uid
        idx._user_to_ids[uid]['account_id'] = acct

    return idx


class IdentityIndex:
    def __init__(self):
        self._email_to_user = {}
        self._user_to_ids = defaultdict(lambda: {
            'emails': set(),
            'phones': set(),
            'email_hashes': set(),
            'user_id': None,
            'account_id': None,
            'name': ''
        })
        self._account_to_user = {}
        self._resource_to_user = {}

    def resolve_email(self, email):
        return self._email_to_user.get(_normalize_email(email))

    def get_identifiers(self, user_id):
        return self._user_to_ids.get(user_id)

    def resolve_account(self, account_id):
        return self._account_to_user.get(account_id)

    def resolve_resource(self, resource_id):
        return self._resource_to_user.get(resource_id)

    def user_matches_identifier(self, user_id, value):
        """Check if a value (email, phone, hash, user_id) matches the user."""
        if value is None:
            return False
        ids = self._user_to_ids.get(user_id)
        if ids is None:
            return False

        if value == user_id:
            return True

        v_lower = value.strip().lower()
        if v_lower in ids['emails']:
            return True

        v_phone = _normalize_phone(value)
        if v_phone and v_phone in ids['phones']:
            return True

        if value.strip() in ids['email_hashes']:
            return True

        return False
