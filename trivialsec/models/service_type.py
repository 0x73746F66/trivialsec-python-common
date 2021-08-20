from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter


__module__ = 'trivialsec.models.service_type'
__table__ = 'service_types'
__pk__ = 'service_type_id'

class ServiceType(MySQL_Row_Adapter):
    STATE_QUEUED = 'queued'
    STATE_STARTING = 'starting'
    STATE_PROCESSING = 'processing'
    STATE_COMPLETED = 'completed'
    STATE_ERROR = 'error'
    STATE_ABORT = 'aborted'
    STATE_FINALISING = 'finalising'

    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.service_type_id = kwargs.get('service_type_id')
        self.name = kwargs.get('name')
        self.category = kwargs.get('category')

class ServiceTypes(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('ServiceType', __table__, __pk__)
