from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter


__module__ = 'trivialsec.models.project'
__table__ = 'projects'
__pk__ = 'project_id'

class Project(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.project_id = kwargs.get('project_id')
        self.account_id = kwargs.get('account_id')
        self.canonical_id = kwargs.get('canonical_id')
        self.name = kwargs.get('name')
        self.created_at = kwargs.get('created_at')
        self.deleted = bool(kwargs.get('deleted'))

    def gen_canonical_id(self) -> str:
        if not self.name:
            raise ValueError('set a project name before generating the canonical_id')
        value = "".join([ c if c.isalnum() else "-" for c in self.name ]).lower()
        super().__setattr__('canonical_id', value)
        return value

    def __setattr__(self, name, value):
        if name in ['deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class Projects(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('Project', __table__, __pk__)
