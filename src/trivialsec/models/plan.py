from trivialsec.helpers.mysql_adapter import MySQL_Row_Adapter, MySQL_Table_Adapter
from decimal import Decimal, ROUND_DOWN

__module__ = 'trivialsec.models.plan'
__table__ = 'plans'
__pk__ = 'plan_id'

class Plan(MySQL_Row_Adapter):
    def __init__(self, **kwargs):
        super().__init__(__table__, __pk__)
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
            value = Decimal(value or 0).quantize(Decimal('.01'), rounding=ROUND_DOWN)
        super().__setattr__(name, value)

class Plans(MySQL_Table_Adapter):
    def __init__(self):
        super().__init__('Plan', __table__, __pk__)
