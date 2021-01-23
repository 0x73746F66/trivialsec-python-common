from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.service_type'

class ServiceType(DatabaseHelpers):
    STATE_QUEUED = 'queued'
    STATE_STARTING = 'starting'
    STATE_PROCESSING = 'processing'
    STATE_COMPLETED = 'completed'
    STATE_ERROR = 'error'
    STATE_ABORT = 'aborted'
    STATE_FINALISING = 'finalising'

    def __init__(self, **kwargs):
        super().__init__('service_types', 'service_type_id')
        self.service_type_id = kwargs.get('service_type_id')
        self.name = kwargs.get('name')
        self.category = kwargs.get('category')

class ServiceTypes(DatabaseIterators):
    def __init__(self):
        super().__init__('ServiceType')
