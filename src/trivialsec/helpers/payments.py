from decimal import Decimal, ROUND_DOWN
from datetime import datetime
import stripe
from stripe.error import RateLimitError, APIConnectionError
from retry.api import retry
from gunicorn.glogging import logging
from trivialsec.helpers.config import config
from trivialsec.models.plan_invoice import PlanInvoice
from trivialsec.models.plan import Plan
from trivialsec.models.account import Account


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers.payments'

stripe.api_version = "2020-08-27"
stripe.api_key = config.stripe_secret_key
if config.http_proxy is not None:
    stripe.proxy = config.http_proxy

@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def get_product(product :str) -> dict:
    if product not in config.stripe.products.keys():
        logger.error(f'attempted to call stripe with invalid product: {product}')
    product_id = config.stripe['products'][product].get('product_id')

    try:
        return stripe.Product.retrieve(product_id)

    except stripe.error.InvalidRequestError:
        logger.error(f'[get_product] Invalid parameters were supplied to Stripe API: {product_id}')
    except stripe.error.AuthenticationError:
        logger.error('[get_product] Authentication with Stripe API failed')
    except stripe.error.StripeError as ex:
        logger.exception(ex)
    except Exception as ex:
        logger.exception(ex)

@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def get_pricing_by_id(price_id :str) -> dict:
    try:
        return stripe.Price.retrieve(price_id)

    except stripe.error.InvalidRequestError:
        logger.error(f'[get_pricing_by_id] Invalid parameters were supplied to Stripe API: {price_id}')
    except stripe.error.AuthenticationError:
        logger.error('[get_pricing_by_id] Authentication with Stripe API failed')
    except stripe.error.StripeError as ex:
        logger.exception(ex)
    except Exception as ex:
        logger.exception(ex)

@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def get_pricing(product :str) -> dict:
    if product not in config.stripe.products.keys():
        logger.error(f'attempted to call stripe with invalid product: {product}')
    if product == 'enterprise':
        return

    return {
        'yearly': get_pricing_by_id(config.stripe['products'][product].get('yearly')),
        'monthly': config.stripe['products'][product].get('monthly'),
    }

@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def create_customer(email :str):
    try:
        return stripe.Customer.create(
            email=email
        )

    except stripe.error.InvalidRequestError:
        logger.error(f'[create_customer] Invalid parameters were supplied to Stripe API: {email}')
    except stripe.error.AuthenticationError:
        logger.error('[create_customer] Authentication with Stripe API failed')
    except Exception as ex:
        logger.exception(ex)

@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def checkout(price_id :str, customer_id :str):
    try:
        return stripe.checkout.Session.create(
            allow_promotion_codes=True,
            mode='subscription',
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            success_url=f"{config.get_app().get('app_url')}/account/setup/3",
            cancel_url=f"{config.get_app().get('app_url')}/account/setup/2",
        )

    except stripe.error.InvalidRequestError:
        logger.error(f'[retry_subscription] Invalid parameters were supplied to Stripe API: price_id {price_id} customer_id {customer_id}')
    except stripe.error.AuthenticationError:
        logger.error('[retry_subscription] Authentication with Stripe API failed')
    except stripe.error.CardError as err:
        logger.error(f'Status is: {err.http_status} Type is: {err.error.type} Code is: {err.error.code} Param is: {err.error.param} Message is: {err.error.message}')
    except Exception as ex:
        logger.exception(ex)

def upsert_plan_invoice(stripe_invoice_data :dict) -> int:
    plan = Plan(stripe_customer_id=stripe_invoice_data['customer'])
    plan.hydrate('stripe_customer_id')
    plan_invoice = PlanInvoice(stripe_invoice_id=stripe_invoice_data['id'])
    plan_invoice.hydrate()
    plan_invoice.plan_id = plan.plan_id
    plan_invoice.hosted_invoice_url = stripe_invoice_data.get('hosted_invoice_url', plan_invoice.hosted_invoice_url)
    plan_invoice.cost = Decimal(int(stripe_invoice_data['total'])/100).quantize(Decimal('.01'), rounding=ROUND_DOWN)
    # plan_invoice.cost = Decimal(int(stripe_invoice_data['lines']['data'][0]['amount'])/100).quantize(Decimal('.01'), rounding=ROUND_DOWN)
    plan_invoice.currency = stripe_invoice_data['lines']['data'][0]['currency'].upper()
    if 'discount' in stripe_invoice_data and isinstance(stripe_invoice_data['discount'], dict) and 'coupon' in stripe_invoice_data['discount']:
        plan_invoice.coupon_code = stripe_invoice_data['discount']['coupon']['id']
        plan_invoice.coupon_desc = stripe_invoice_data['discount']['coupon']['name']
        plan_invoice.stripe_promotion_id = stripe_invoice_data['discount']['promotion_code']
    plan_invoice.interval = stripe_invoice_data['lines']['data'][0]['plan']['interval'].upper()
    plan_invoice.status = stripe_invoice_data['status']
    plan_invoice.due_date = datetime.fromtimestamp(stripe_invoice_data['created']).isoformat()
    if plan_invoice.created_at is None:
        plan_invoice.created_at = datetime.utcnow()
    try:
        plan_invoice.persist()
    except Exception as ex:
        logger.exception(ex)
    return plan_invoice.plan_id

def payment_intent_succeeded(stripe_customer :str, stripe_charge_data :dict):
    plan = Plan(stripe_customer_id=stripe_customer)
    if plan.hydrate('stripe_customer_id'):
        plan.stripe_payment_method_id = stripe_charge_data['payment_method']
        plan.stripe_card_brand = stripe_charge_data['payment_method_details']['card']['brand']
        plan.stripe_card_last4 = stripe_charge_data['payment_method_details']['card']['last4']
        plan.stripe_card_expiry_month = stripe_charge_data['payment_method_details']['card']['exp_month']
        plan.stripe_card_expiry_year = stripe_charge_data['payment_method_details']['card']['exp_year']
        plan.persist()
        return plan.plan_id

    return f'missing stripe_customer_id {stripe_customer}'

def invoice_paid(stripe_customer :str, stripe_data :dict):
    plan = Plan(stripe_customer_id=stripe_customer)
    if plan.hydrate('stripe_customer_id'):
        plan.currency = stripe_data['currency'].upper()
        plan.interval = stripe_data['lines']['data'][0]['plan']['interval'].upper()
        plan.cost = Decimal(int(stripe_data['subtotal'])/100).quantize(Decimal('.01'), rounding=ROUND_DOWN)
        plan.stripe_product_id = stripe_data['lines']['data'][0]['price']['product']
        plan.stripe_price_id = stripe_data['lines']['data'][0]['price']['id']
        plan.stripe_subscription_id = stripe_data['lines']['data'][0]['subscription']
        plan.name = stripe_data['lines']['data'][0]['description'].replace('1 × ', '')
        plan.persist()
        account = Account(account_id=plan.account_id)
        account.hydrate()
        if account.is_setup is False:
            account.is_setup = True
            account.persist()
        return upsert_plan_invoice(stripe_data)

    return f'missing stripe_customer_id {stripe_customer}'

def subscription_created(stripe_customer :str, stripe_subscription_id :str, default_payment_method :str, stripe_plan_data :dict):
    plan = Plan(stripe_customer_id=stripe_customer)
    if plan.hydrate('stripe_customer_id'):
        plan.stripe_subscription_id = stripe_subscription_id
        plan.stripe_product_id = stripe_plan_data['product']
        plan.stripe_price_id = stripe_plan_data['id']
        plan.stripe_payment_method_id = default_payment_method
        plan.cost = Decimal(int(stripe_plan_data['amount_decimal'])/100).quantize(Decimal('.01'), rounding=ROUND_DOWN)
        plan.currency = stripe_plan_data['currency'].upper()
        plan.interval = stripe_plan_data['interval'].upper()
        plan.persist()
        account = Account(account_id=plan.account_id)
        account.hydrate()
        if account.is_setup is False:
            account.is_setup = True
            account.persist()
        return plan.plan_id

    return f'missing stripe_customer_id {stripe_customer}'
