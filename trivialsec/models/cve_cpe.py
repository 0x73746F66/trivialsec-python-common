from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators

__module__ = 'trivialsec.models.cve_cpe'
__table__ = 'cve_cpes'
__pk__ = 'cve_id'

class CPE(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.cve_id = kwargs.get('cve_id')
        self.cpe = kwargs.get('cpe')
        self.version_end_excluding = kwargs.get('version_end_excluding')

class CPEs(DatabaseIterators):
    def __init__(self):
        super().__init__('CPE', __table__, __pk__)
