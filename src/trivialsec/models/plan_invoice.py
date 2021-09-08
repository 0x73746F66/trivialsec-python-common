from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter

__module__ = 'trivialsec.models.plan_invoice'
__table__ = 'plan_invoices'
__pk__ = 'plan_id'

class PlanInvoice(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
        self.plan_id = kwargs.get('plan_id')
        self.stripe_invoice_id = kwargs.get('stripe_invoice_id')
        self.hosted_invoice_url = kwargs.get('hosted_invoice_url')
        self.cost = kwargs.get('cost')
        self.currency = kwargs.get('currency')
        self.coupon_code = kwargs.get('coupon_code')
        self.coupon_desc = kwargs.get('coupon_desc')
        self.stripe_promotion_id = kwargs.get('stripe_promotion_id')
        self.interval = kwargs.get('interval')
        self.status = kwargs.get('status')
        self.due_date = kwargs.get('due_date')
        self.created_at = kwargs.get('created_at')

class PlanInvoices(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('PlanInvoice', __table__, __pk__)
