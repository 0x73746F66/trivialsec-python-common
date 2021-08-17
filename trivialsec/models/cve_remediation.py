from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators

__module__ = 'trivialsec.models.cve_remediation'
__table__ = 'cve_remediation'
__pk__ = 'cve_id'

class CVERemediation(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.cve_id = kwargs.get('cve_id')
        self.type = kwargs.get('type')
        self.source = kwargs.get('source')
        self.source_id = kwargs.get('source_id')
        self.source_url = kwargs.get('source_url')
        self.description = kwargs.get('description')
        self.published_at = kwargs.get('published_at')

    def __setattr__(self, name, value):
        if name in ['verified']:
            value = bool(value)
        super().__setattr__(name, value)

class CVERemediations(DatabaseIterators):
    def __init__(self):
        super().__init__('CVERemediation', __table__, __pk__)
