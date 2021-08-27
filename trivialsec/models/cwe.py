from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter, replica_adapter
from .cve import CVE


__module__ = 'trivialsec.models.cwe'
__table__ = 'cwes'
__pk__ = 'cwe_id'

class CWE(MySQL_Row_Adapter):
    cves = []
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.cwe_id = kwargs.get('cwe_id')
        self.name = kwargs.get('name')
        self.description = kwargs.get('description')
        self.status = kwargs.get('status')
        self.introduced = kwargs.get('introduced')
        self.impact = kwargs.get('impact')
        self.detection = kwargs.get('detection')
        self.mitigation = kwargs.get('mitigation')
        self.platform = kwargs.get('platform')
        self.platform_windows = bool(kwargs.get('platform_windows'))
        self.platform_macos = bool(kwargs.get('platform_macos'))
        self.platform_unix = bool(kwargs.get('platform_unix'))
        self.platform_language = kwargs.get('platform_language')

    def __setattr__(self, name, value):
        if name in ['platform_windows', 'platform_macos', 'platform_unix']:
            value = bool(value)
        super().__setattr__(name, value)

    def get_cves(self):
        stmt = "SELECT cve_id FROM cwe_cve WHERE cwe_id = %(cwe_id)s"
        with replica_adapter as sql:
            results = sql.query(stmt, {'cwe_id': self.cwe_id})
            for val in results:
                if not any(isinstance(x, CVE) and x.cve_id == val['cve_id'] for x in self.cves):
                    member = CVE(cve_id=val['cve_id'])
                    if member.hydrate():
                        self.cves.append(member)

        return self

    def add_cve(self, cve: CVE) -> bool:
        insert_stmt = "INSERT INTO cwe_cve (cwe_id, cve_id) VALUES (%(cwe_id)s, %(cve_id)s) ON DUPLICATE KEY UPDATE cve_id=cve_id;"
        with replica_adapter as sql:
            new_id = sql.query(insert_stmt, {'cve_id': cve.cve_id, 'cwe_id': self.cwe_id})
            if new_id:
                self.cves.append(cve)
                return True

class CWEs(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('CVE', __table__, __pk__)
