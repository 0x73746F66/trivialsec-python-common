from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators


__module__ = 'trivialsec.models.program'

class Program(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('programs', 'program_id')
        self.program_id = kwargs.get('program_id')
        self.name = kwargs.get('name')
        self.external_url = kwargs.get('external_url')
        self.icon_url = kwargs.get('icon_url')
        self.category = kwargs.get('category')

class Programs(DatabaseIterators):
    def __init__(self):
        super().__init__('Program')

class InventoryItem(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('inventory_items', 'inventory_item_id')
        self.inventory_item_id = kwargs.get('inventory_item_id')
        self.program_id = kwargs.get('program_id')
        self.project_id = kwargs.get('project_id')
        self.domain_id = kwargs.get('domain_id')
        self.version = kwargs.get('version')
        self.source_description = kwargs.get('source_description')
        self.created_at = kwargs.get('created_at')
        self.last_checked = kwargs.get('last_checked')

class InventoryItems(DatabaseIterators):
    def __init__(self):
        super().__init__('InventoryItem')
