from decimal import Decimal, ROUND_DOWN
from trivialsec.helpers.elasticsearch_adapter import Elasticsearch_Collection_Adapter, Elasticsearch_Document_Adapter


__module__ = 'trivialsec.models.cve'
__index__ = 'cves'
__pk__ = 'cve_id'

class CVE(Elasticsearch_Document_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__index__, __pk__)
        self.cve_id = kwargs.get('cve_id')
        self.assigner = kwargs.get('assigner')
        self.title = kwargs.get('title')
        self.description = kwargs.get('description')
        self.cvss_version = kwargs.get('cvss_version')
        self.vector = kwargs.get('vector')
        self.base_score = kwargs.get('base_score')
        self.exploitability_score = kwargs.get('exploitability_score')
        self.impact_score = kwargs.get('impact_score')
        self.temporal_score = kwargs.get('temporal_score')
        self.reported_at = kwargs.get('reported_at')
        self.published_at = kwargs.get('published_at')
        self.last_modified = kwargs.get('created_at')
        self.cwe = kwargs.get('cwe', [])
        self.cpe = kwargs.get('cpe', [])
        self.references = kwargs.get('references', [])
        self.remediation = kwargs.get('remediation', [])
        self.exploit = kwargs.get('exploit', [])

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

    @staticmethod
    def vector_to_dict(vector :str, version :int = 3) -> dict:
        vector_data = {
            'v2': {
                'CVSS': '2.0',
                'AV': None,
                'AC': None,
                'Au': None,
                'C': None,
                'I': None,
                'A': None,
                'E': 'ND',
                'RL': 'ND',
                'RC': 'ND',
                'CDP': 'ND',
                'TD': 'ND',
                'CR': 'ND',
                'IR': 'ND',
                'AR': 'ND',
            },
            'v3': {
                'CVSS': '3.1',
                'AV': None,
                'AC': None,
                'PR': None,
                'UI': None,
                'S': None,
                'C': None,
                'I': None,
                'A': None,
                'E': 'X',
                'RL': 'X',
                'RC': 'X',
                'MAV': 'X',
                'MAC': 'X',
                'MPR': 'X',
                'MUI': 'X',
                'MS': 'X',
                'MC': 'X',
                'MI': 'X',
                'MA': 'X',
                'CR': 'X',
                'IR': 'X',
                'AR': 'X',
            }
        }
        for vec in vector.split('/'):
            key, setting = vec.split(':')
            vector_data[f'v{version}'][key] = setting
        return vector_data[f'v{version}']

    @staticmethod
    def dict_to_vector(vector_data :dict, version :int = 3) -> str:
        required = {
            'v2': ['AV', 'AC', 'Au', 'C', 'I', 'A'],
            'v3': ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A']
        }
        vector_values = {
            'v2': {
                'CVSS': ['2.0'],
                'AV': ['L', 'A', 'N'],
                'AC': ['H', 'M', 'L'],
                'Au': ['M', 'S', 'N'],
                'C': ['N', 'P', 'C'],
                'I': ['N', 'P', 'C'],
                'A': ['N', 'P', 'C'],
                'E': ['ND', 'U', 'POC', 'F', 'H'],
                'RL': ['ND', 'OF', 'TF', 'W', 'U'],
                'RC': ['ND', 'UC', 'UR', 'C'],
                'CDP': ['ND', 'N', 'L', 'LM', 'MH', 'H'],
                'TD': ['ND', 'N', 'L', 'M', 'H'],
                'CR': ['ND', 'L', 'M', 'H'],
                'IR': ['ND', 'L', 'M', 'H'],
                'AR': ['ND', 'L', 'M', 'H'],
            },
            'v3': {
                'CVSS': ['3.0', '3.1'],
                'AV': ['N', 'A', 'L', 'P'],
                'AC': ['L', 'H'],
                'PR': ['N', 'L', 'H'],
                'UI': ['N', 'R'],
                'S': ['U', 'C'],
                'C': ['N', 'L', 'H'],
                'I': ['N', 'L', 'H'],
                'A': ['N', 'L', 'H'],
                'E': ['X', 'U', 'P', 'F', 'H'],
                'RL': ['X', 'O', 'T', 'W', 'U'],
                'RC': ['X', 'U', 'R', 'C'],
                'MAV': ['X', 'N', 'A'],
                'MAC': ['X', 'L', 'H'],
                'MPR': ['X', 'N', 'L', 'H'],
                'MUI': ['X', 'N', 'R'],
                'MS': ['X', 'U', 'C'],
                'MC': ['X', 'N', 'L', 'H'],
                'MI': ['X', 'N', 'L', 'H'],
                'MA': ['X', 'N', 'L', 'H'],
                'CR': ['X', 'L', 'M', 'H'],
                'IR': ['X', 'L', 'M', 'H'],
                'AR': ['X', 'L', 'M', 'H'],
            }
        }
        for req in required[f'v{version}']:
            if req not in vector_data or vector_data[req] not in vector_values[f'v{version}'][req]:
                raise ValueError(f'dict_to_vector expected "{req}" vector v{version}')
        vector = []
        for req in vector_values[f'v{version}'].keys():
            if req in vector_data:
                if vector_data[req] not in vector_values[f'v{version}'][req]:
                    raise ValueError(f'Incorrect value "{vector_data[req]}" for {req} vector v{version}')
                vector.append(f'{req}:{vector_data[req]}')
        return '/'.join(vector)

class CVEs(Elasticsearch_Collection_Adapter):
    def __init__(self):
        super().__init__('CVE', __index__, __pk__)
