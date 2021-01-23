from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators
from trivialsec.helpers.database import mysql_adapter
from .member import Member

__module__ = 'trivialsec.models.finding'

class Finding(DatabaseHelpers):
    CONFIDENCE_HIGH_RGB = [7, 189, 152]
    CONFIDENCE_MEDIUM_RGB = [15, 145, 119]
    CONFIDENCE_LOW_RGB = [0, 90, 72]
    SEVERITY_INFO_RGB = [103, 154, 255]
    SEVERITY_LOW_RGB = [53, 167, 30]
    SEVERITY_MEDIUM_RGB = [255, 183, 48]
    SEVERITY_HIGH_RGB = [255, 107, 48]
    SEVERITY_CRITICAL_RGB = [121, 18, 18]
    CRITICALITY_INFO_RGB = [44, 192, 255]
    CRITICALITY_LOW_RGB = [0, 162, 232]
    CRITICALITY_MEDIUM_RGB = [5, 100, 140]
    CRITICALITY_HIGH_RGB = [5, 72, 100]
    CRITICALITY_CRITICAL_RGB = [5, 48, 66]

    RATING_NONE = 'NOT SCORED'
    RATING_INFO = 'INFO'
    RATING_LOW = 'LOW'
    RATING_MEDIUM = 'MEDIUM'
    RATING_HIGH = 'HIGH'
    RATING_CRITICAL = 'CRITICAL'
    CONFIDENCE_HIGH = 'HIGH'
    CONFIDENCE_MEDIUM = 'MEDIUM'
    CONFIDENCE_LOW = 'LOW'
    WORKFLOW_NEW = 'NEW'
    WORKFLOW_ASSIGNED = 'ASSIGNED'
    WORKFLOW_IN_PROGRESS = 'IN_PROGRESS'
    WORKFLOW_RESOLVED = 'RESOLVED'
    WORKFLOW_DEFERRED = 'DEFERRED'
    WORKFLOW_DUPLICATE = 'DUPLICATE'
    WORKFLOW_MAP = {
        'DUPLICATE': 'Duplicate',
        'DEFERRED': 'Deferred',
        'RESOLVED': 'Resolved',
        'IN_PROGRESS': 'In Progress',
        'ASSIGNED': 'Assigned',
        'NEW': 'New',
    }
    VERIFY_UNKNOWN = 'UNKNOWN'
    VERIFY_TRUE_POSITIVE = 'TRUE_POSITIVE'
    VERIFY_FALSE_POSITIVE = 'FALSE_POSITIVE'
    VERIFY_BENIGN_POSITIVE = 'BENIGN_POSITIVE'
    VERIFY_MAP = {
        'UNKNOWN': 'Unknown',
        'BENIGN_POSITIVE': 'Not Vulnerable',
        'FALSE_POSITIVE': 'False Positive',
        'TRUE_POSITIVE': 'Vulnerable',
    }
    STATE_ACTIVE = 'ACTIVE'
    STATE_ARCHIVED = 'ARCHIVED'

    def __init__(self, **kwargs):
        super().__init__('findings', 'finding_id')
        self.finding_id = kwargs.get('finding_id')
        self.finding_detail_id = kwargs.get('finding_detail_id')
        self.account_id = kwargs.get('account_id')
        self.project_id = kwargs.get('project_id')
        self.domain_id = kwargs.get('domain_id')
        self.assignee_id = kwargs.get('assignee_id')
        self.service_type_id = kwargs.get('service_type_id')
        self.source_description = kwargs.get('source_description')
        self.is_passive = bool(kwargs.get('is_passive'))
        self.severity_normalized = kwargs.get('severity_normalized', 0)
        self.verification_state = kwargs.get('verification_state')
        self.workflow_state = kwargs.get('workflow_state')
        self.state = kwargs.get('state')
        self.evidence = kwargs.get('evidence')
        self.created_at = kwargs.get('created_at')
        self.updated_at = kwargs.get('updated_at')
        self.defer_to = kwargs.get('defer_to')
        self.last_observed_at = kwargs.get('last_observed_at')
        self.archived = bool(kwargs.get('archived'))
        self.notes = []
        self.watchers = []

    def __setattr__(self, name, value):
        if name in ['archived']:
            value = bool(value)
        super().__setattr__(name, value)

    def get_watchers(self):
        sql = "SELECT member_id FROM finding_watchers WHERE finding_id = %(finding_id)s"
        with mysql_adapter as database:
            results = database.query(sql, {'finding_id': self.finding_id})
            for val in results:
                if not any(isinstance(x, Member) and x.member_id == val['member_id'] for x in self.watchers):
                    member = Member(member_id=val['member_id'])
                    if member.hydrate():
                        self.watchers.append(member)

        return self

    def add_watcher(self, member: Member) -> bool:
        insert_stmt = "INSERT INTO finding_watchers (member_id, finding_id) VALUES (%(member_id)s, %(finding_id)s) ON DUPLICATE KEY UPDATE finding_id=finding_id;"
        with mysql_adapter as database:
            new_id = database.query(insert_stmt, {'member_id': member.member_id, 'finding_id': self.finding_id})
            if new_id:
                self.watchers.append(member)
                return True

        return False

    def get_notes(self):
        sql = "SELECT finding_note_id FROM finding_notes WHERE finding_id = %(finding_id)s"
        with mysql_adapter as database:
            results = database.query(sql, {'finding_id': self.finding_id})
            for val in results:
                if not any(isinstance(x, FindingNote) and x.finding_note_id == val['finding_note_id'] for x in self.notes):
                    note = FindingNote(finding_note_id=val['finding_note_id'])
                    if note.hydrate():
                        self.notes.append(note)

        return self

class Findings(DatabaseIterators):
    def __init__(self):
        super().__init__('Finding')

    def load_details(self):
        items = []
        for finding in self:
            detail = FindingDetail(finding_detail_id=finding.finding_detail_id)
            detail.hydrate()
            for col in detail.cols():
                setattr(finding, f'detail_{col}', getattr(detail, col))
            items.append(finding)
        self.set_items(items)
        return self

class FindingDetail(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('finding_details', 'finding_detail_id')
        self.finding_detail_id = kwargs.get('finding_detail_id')
        self.title = kwargs.get('title')
        self.description = kwargs.get('description')
        self.type_namespace = kwargs.get('type_namespace')
        self.type_category = kwargs.get('type_category')
        self.type_classifier = kwargs.get('type_classifier')
        self.criticality = kwargs.get('severity_product')
        self.confidence = kwargs.get('severity_product')
        self.severity_product = kwargs.get('severity_product')
        self.recommendation = kwargs.get('recommendation')
        self.recommendation_url = kwargs.get('recommendation_url')
        self.cvss_vector = kwargs.get('cvss_vector')
        self.created_at = kwargs.get('created_at')
        self.review = kwargs.get('review')
        self.updated_at = kwargs.get('updated_at')
        self.modified_by_id = kwargs.get('modified_by_id')

class FindingDetails(DatabaseIterators):
    def __init__(self):
        super().__init__('FindingDetail')

class FindingNote(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('finding_notes', 'finding_note_id')
        self.finding_note_id = kwargs.get('finding_note_id')
        self.finding_id = kwargs.get('finding_id')
        self.member_id = kwargs.get('member_id')
        self.text = kwargs.get('text')
        self.updated_at = kwargs.get('updated_at')
        self.deleted = bool(kwargs.get('deleted'))

    def __setattr__(self, name, value):
        if name in ['deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class FindingNotes(DatabaseIterators):
    def __init__(self):
        super().__init__('FindingNote')
