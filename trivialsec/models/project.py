from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.project'
__table__ = 'projects'
__pk__ = 'project_id'

class Project(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.project_id = kwargs.get('project_id')
        self.account_id = kwargs.get('account_id')
        self.name = kwargs.get('name')
        self.created_at = kwargs.get('created_at')
        self.deleted = bool(kwargs.get('deleted'))

    def __setattr__(self, name, value):
        if name in ['deleted']:
            value = bool(value)
        super().__setattr__(name, value)

class Projects(DatabaseIterators):
    def __init__(self):
        super().__init__('Project', __table__, __pk__)
