from trivialsec.helpers.elasticsearch_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter


__module__ = 'trivialsec.models.cwe'
__index__ = 'cwes'
__pk__ = 'cwe_id'

class CWE(Elasticsearch_Document_Adapter):
    cves = []
    def __init__(self, **kwargs):
        super().__init__(__index__, __pk__)
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

class CWEs(Elasticsearch_Collection_Adapter):
    def __init__(self):
        super().__init__('CWE', __index__, __pk__)
