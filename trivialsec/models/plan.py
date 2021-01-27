from trivialsec.helpers.database import DatabaseHelpers, DatabaseIterators
from decimal import Decimal, ROUND_DOWN


__module__ = 'trivialsec.models.plan'

class Plan(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('plans', 'plan_id')
        self.plan_id = kwargs.get('plan_id')
        self.account_id = kwargs.get('account_id')
        self.name = kwargs.get('name')
        self.is_dedicated = bool(kwargs.get('is_dedicated', False))
        self.stripe_customer_id = kwargs.get('stripe_customer_id')
        self.stripe_product_id = kwargs.get('stripe_product_id')
        self.stripe_price_id = kwargs.get('stripe_price_id')
        self.stripe_subscription_id = kwargs.get('stripe_subscription_id')
        self.stripe_payment_method_id = kwargs.get('stripe_payment_method_id')
        self.stripe_card_brand = kwargs.get('stripe_card_brand')
        self.stripe_card_last4 = kwargs.get('stripe_card_last4')
        self.stripe_card_expiry_month = kwargs.get('stripe_card_expiry_month')
        self.stripe_card_expiry_year = kwargs.get('stripe_card_expiry_year')
        self.cost = Decimal(kwargs.get('cost', 0)).quantize(Decimal('.01'), rounding=ROUND_DOWN)
        self.currency = kwargs.get('currency')
        self.interval = kwargs.get('interval')
        self.retention_days = kwargs.get('retention_days', 32)
        self.on_demand_passive_daily = kwargs.get('on_demand_passive_daily', 10)
        self.on_demand_active_daily = kwargs.get('on_demand_active_daily', 1)
        self.domains_monitored = kwargs.get('domains_monitored', 1)
        self.webhooks = bool(kwargs.get('webhooks', True))
        self.threatintel = bool(kwargs.get('threatintel', True))
        self.typosquatting = bool(kwargs.get('typosquatting'))
        self.compromise_indicators = bool(kwargs.get('compromise_indicators'))
        self.source_code_scans = bool(kwargs.get('source_code_scans', False))
        self.compliance_reports = bool(kwargs.get('compliance_reports', False))

    def __setattr__(self, name, value):
        if name in ['is_dedicated', 'compliance_reports', 'webhooks', 'source_code_scans', 'threatintel', 'compromise_indicators', 'typosquatting']:
            value = bool(value)
        elif name in 'cost':
            value = Decimal(value).quantize(Decimal('.01'), rounding=ROUND_DOWN)
        super().__setattr__(name, value)

class Plans(DatabaseIterators):
    def __init__(self):
        super().__init__('Plan')

class PlanInvoice(DatabaseHelpers):
    def __init__(self, **kwargs):
        super().__init__('plan_invoices', 'plan_id')
        self.plan_id = kwargs.get('plan_id')
        self.stripe_invoice_id = kwargs.get('stripe_invoice_id')
        self.hosted_invoice_url = kwargs.get('hosted_invoice_url')
        self.cost = kwargs.get('cost')
        self.currency = kwargs.get('currency')
        self.interval = kwargs.get('interval')
        self.status = kwargs.get('status')
        self.due_date = kwargs.get('due_date')
        self.created_at = kwargs.get('created_at')

class PlanInvoices(DatabaseIterators):
    def __init__(self):
        super().__init__('PlanInvoice')
