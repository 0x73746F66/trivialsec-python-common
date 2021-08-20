from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter

__module__ = 'trivialsec.models.cve_reference'
__table__ = 'cve_references'
__pk__ = 'cve_id'

class CVEReference(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.cve_id = kwargs.get('cve_id')
        self.url = kwargs.get('url')
        self.name = kwargs.get('name')
        self.source = kwargs.get('source')
        self.tags = kwargs.get('tags')

class CVEReferences(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('CVEReference', __table__, __pk__)
