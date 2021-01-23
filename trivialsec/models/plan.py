from trivialsec.models import DatabaseHelpers, DatabaseIterators
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
        self.retention_days = kwargs.get('retention_days', 32)
        self.active_daily = kwargs.get('active_daily', 1)
        self.scheduled_active_daily = kwargs.get('scheduled_active_daily', 0)
        self.passive_daily = kwargs.get('passive_daily', 10)
        self.scheduled_passive_daily = kwargs.get('scheduled_passive_daily', 0)
        self.git_integration_daily = kwargs.get('git_integration_daily', 0)
        self.source_code_daily = kwargs.get('source_code_daily', 0)
        self.dependency_support_rating = kwargs.get('dependency_support_rating', 0)
        self.alert_email = bool(kwargs.get('alert_email'))
        self.alert_integrations = bool(kwargs.get('alert_integrations'))
        self.threatintel = bool(kwargs.get('threatintel'))
        self.compromise_indicators = bool(kwargs.get('compromise_indicators'))
        self.typosquatting = bool(kwargs.get('typosquatting'))

    def __setattr__(self, name, value):
        if name in ['is_dedicated', 'alert_email', 'alert_integrations', 'threatintel', 'compromise_indicators', 'typosquatting']:
            value = bool(value)
        super().__setattr__(name, value)

class Plans(DatabaseIterators):
    def __init__(self):
        super().__init__('Plan')
