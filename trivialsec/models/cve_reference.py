from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators

__module__ = 'trivialsec.models.cve_reference'
__table__ = 'cve_references'
__pk__ = 'cve_id'

class CVEReference(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.cve_id = kwargs.get('cve_id')
        self.url = kwargs.get('url')
        self.name = kwargs.get('name')
        self.source = kwargs.get('source')
        self.tags = kwargs.get('tags')

class CVEReferences(DatabaseIterators):
    def __init__(self):
        super().__init__('CVEReference', __table__, __pk__)
