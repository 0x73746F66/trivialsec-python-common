from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter

__module__ = 'trivialsec.models.finding_note'
__table__ = 'finding_notes'
__pk__ = 'finding_note_id'

class FindingNote(MySQL_Row_Adapter):
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

class FindingNotes(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('FindingNote', __table__, __pk__)
