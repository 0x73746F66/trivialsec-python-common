from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter

__module__ = 'trivialsec.models.inventory'
__table__ = 'inventory_items'
__pk__ = 'inventory_item_id'

class InventoryItem(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.inventory_item_id = kwargs.get('inventory_item_id')
        self.program_id = kwargs.get('program_id')
        self.project_id = kwargs.get('project_id')
        self.domain_id = kwargs.get('domain_id')
        self.version = kwargs.get('version')
        self.source_description = kwargs.get('source_description')
        self.created_at = kwargs.get('created_at')
        self.last_checked = kwargs.get('last_checked')

class InventoryItems(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('InventoryItem', __table__, __pk__)
