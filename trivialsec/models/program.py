from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter


__module__ = 'trivialsec.models.program'
__table__ = 'programs'
__pk__ = 'program_id'

class Program(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.program_id = kwargs.get('program_id')
        self.name = kwargs.get('name')
        self.external_url = kwargs.get('external_url')
        self.icon_url = kwargs.get('icon_url')
        self.category = kwargs.get('category')

class Programs(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('Program', __table__, __pk__)
