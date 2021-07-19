from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators

__module__ = 'trivialsec.models.finding_note'
__table__ = 'finding_notes'
__pk__ = 'finding_note_id'

class FindingNote(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
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
        super().__init__('FindingNote', __table__, __pk__)
