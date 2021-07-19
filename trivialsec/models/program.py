from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.program'
__table__ = 'programs'
__pk__ = 'program_id'

class Program(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.program_id = kwargs.get('program_id')
        self.name = kwargs.get('name')
        self.external_url = kwargs.get('external_url')
        self.icon_url = kwargs.get('icon_url')
        self.category = kwargs.get('category')

class Programs(DatabaseIterators):
    def __init__(self):
        super().__init__('Program', __table__, __pk__)
