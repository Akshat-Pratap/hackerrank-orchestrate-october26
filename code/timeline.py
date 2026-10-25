"""Timeline builder: index system_activity events by user, resource, time."""
from collections import defaultdict


def build_timeline(system_activity):
    """Build a Timeline from system_activity rows.

    Provides:
      - get_events_for_resource(resource_id) -> sorted list of events
      - get_events_for_user(user_id) -> sorted list of events (via resource mapping)
      - classify_request_accounts: set of account_ids classified as non-deletion
      - resource_identity_links: dict resource_id -> {user_id, email}
    """
    tl = Timeline()

    for act in system_activity:
        event = {
            'activity_id': act['activity_id'],
            'event_time': act['event_time'],
            'event_type': act['event_type'],
            'source_system': act['source_system'],
            'target_system': act['target_system'],
            'resource_id': act['resource_id'],
            'reported_result': act['reported_result'],
            'details': act['details'],
        }

        tl._by_resource[act['resource_id']].append(event)

        if act['event_type'] == 'CLASSIFY_REQUEST':
            tl.classify_request_accounts.add(act['resource_id'])

        if act['event_type'] == 'LINK_RESOURCE_IDENTITY':
            import re
            m_user = re.search(r'user_(\d+)', act['details'])
            m_email = re.search(r'to\s+([\w.+\-]+@[\w.\-]+)\s+and', act['details'])
            if m_user:
                uid = f'user_{m_user.group(1)}'
                tl.resource_identity_links[act['resource_id']] = {
                    'user_id': uid,
                    'email': m_email.group(1).lower() if m_email else None,
                }

        # Index by source and target system
        tl._all_events.append(event)

    # Sort all lists
    for k in tl._by_resource:
        tl._by_resource[k].sort(key=lambda e: e['event_time'])
    tl._all_events.sort(key=lambda e: e['event_time'])

    return tl


class Timeline:
    def __init__(self):
        self._by_resource = defaultdict(list)
        self._all_events = []
        self.classify_request_accounts = set()
        self.resource_identity_links = {}

    def get_events_for_resource(self, resource_id):
        return self._by_resource.get(resource_id, [])

    def get_all_events(self):
        return self._all_events

    def get_events_before(self, resource_id, cutoff_time):
        """Get events for a resource with event_time <= cutoff_time."""
        events = self._by_resource.get(resource_id, [])
        return [e for e in events if e['event_time'] <= cutoff_time]
