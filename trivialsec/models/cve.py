from decimal import Decimal, ROUND_DOWN
from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators

__module__ = 'trivialsec.models.cve'
__table__ = 'cves'
__pk__ = 'cve_id'

class CVE(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.cve_id = kwargs.get('cve_id')
        self.assigner = kwargs.get('assigner')
        self.description = kwargs.get('description')
        self.cvss_version = kwargs.get('cvss_version')
        self.vector = kwargs.get('vector')
        self.base_score = kwargs.get('base_score')
        self.exploitability_score = kwargs.get('exploitability_score')
        self.impact_score = kwargs.get('impact_score')
        self.published_at = kwargs.get('published_at')
        self.last_modified = kwargs.get('created_at')

    def __setattr__(self, name, value):
        if name in ['base_score', 'exploitability_score', 'impact_score']:
            value = Decimal(value or 0).quantize(Decimal('.1'), rounding=ROUND_DOWN)
        super().__setattr__(name, value)

    @property
    def rating(self):
        if self.cvss_version in ['3.0', '3.1']:
            if self.base_score >= 0.1 and self.base_score < 4.0:
                return 'Low'
            if self.base_score >= 4.0 and self.base_score < 7.0:
                return 'Medium'
            if self.base_score >= 7.0 and self.base_score < 9.0:
                return 'High'
            if self.base_score >= 9.0:
                return 'Critical'
        if self.cvss_version == '2.0':
            if self.base_score >= 0 and self.base_score < 4.0:
                return 'Low'
            if self.base_score >= 4.0 and self.base_score < 7.0:
                return 'Medium'
            if self.base_score >= 7.0:
                return 'High'
        return None

class CVEs(DatabaseIterators):
    def __init__(self):
        super().__init__('CVE', __table__, __pk__)
