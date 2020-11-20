import json
import stripe
from stripe.error import RateLimitError, APIConnectionError
from retry.api import retry
from decimal import Decimal, ROUND_DOWN
from trivialsec.helpers.log_manager import logger
from trivialsec.helpers.config import config
from trivialsec import models

stripe.api_version = "2020-08-27"
stripe.api_key = config.stripe_secret_key
if config.http_proxy is not None:
    stripe.proxy = config.http_proxy

@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def get_product(product: str) -> dict:
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
def get_pricing_by_id(price_id: str) -> dict:
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
def get_pricing(product: str) -> dict:
    if product not in config.stripe.products.keys():
        logger.error(f'attempted to call stripe with invalid product: {product}')
    if product == 'enterprise':
        return

    return {
        'yearly': get_pricing_by_id(config.stripe['products'][product].get('yearly')),
        'monthly': config.stripe['products'][product].get('monthly'),
    }

@retry((RateLimitError, APIConnectionError), tries=5, delay=1.5, backoff=3)
def create_customer(email: str):
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
def checkout(price_id: str, customer_id: str):
    try:
        return stripe.checkout.Session.create(
            mode='subscription',
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': price_id,
                'quantity': 1,
            }],
            success_url=f"{config.frontend.get('site_scheme')}{config.frontend.get('site_domain')}/account/setup/3",
            cancel_url=f"{config.frontend.get('site_scheme')}{config.frontend.get('site_domain')}/account/setup/2",
        )

    except stripe.error.InvalidRequestError:
        logger.error(f'[retry_subscription] Invalid parameters were supplied to Stripe API: price_id {price_id} customer_id {customer_id}')
    except stripe.error.AuthenticationError:
        logger.error('[retry_subscription] Authentication with Stripe API failed')
    except stripe.error.CardError as err:
        logger.error(f'Status is: {err.http_status} Type is: {err.error.type} Code is: {err.error.code} Param is: {err.error.param} Message is: {err.error.message}')
    except Exception as ex:
        logger.exception(ex)

def webhook_received(request):
    # You can use webhooks to receive information about asynchronous payment events.
    # For more about our webhook events check out https://stripe.com/docs/webhooks.
    webhook_secret = config.stripe_webhook_secret
    request_data = json.loads(request.data)

    if webhook_secret:
        # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
        signature = request.headers.get('stripe-signature')
        try:
            event = stripe.Webhook.construct_event(
                payload=request.data, sig_header=signature, secret=webhook_secret)
            data = event['data']['object']
        except Exception as ex:
            logger.exception(ex)
            return
        # Get the type of webhook event sent - used to check the status of PaymentIntents.
        event_type = event['type']
    else:
        data = request_data['data']['object']
        event_type = request_data['type']

    logger.info(f"[{event_type}]\n{data}")

    if event_type == 'payment_intent.succeeded':
        plan = models.Plan(stripe_customer_id=data['customer'])
        plan.hydrate('stripe_customer_id')
        plan.stripe_payment_method_id = data['charges']['data'][0]['payment_method']
        plan.stripe_card_brand = data['charges']['data'][0]['payment_method_details']['card']['brand']
        plan.stripe_card_last4 = data['charges']['data'][0]['payment_method_details']['card']['last4']
        plan.stripe_card_expiry_month = data['charges']['data'][0]['payment_method_details']['card']['exp_month']
        plan.stripe_card_expiry_year = data['charges']['data'][0]['payment_method_details']['card']['exp_year']
        plan.persist()

    elif event_type == 'invoice.paid':
        plan = models.Plan(stripe_customer_id=data['customer'])
        plan.hydrate('stripe_customer_id')
        plan.currency = data['currency'].upper()
        plan.cost = Decimal(int(data['subtotal'])/100).quantize(Decimal('.01'), rounding=ROUND_DOWN)
        plan.stripe_product_id = data['lines']['data'][0]['price']['product']
        plan.stripe_price_id = data['lines']['data'][0]['price']['id']
        plan.stripe_subscription_id = data['lines']['data'][0]['subscription']
        plan.name = data['lines']['data'][0]['description'].replace('1 × ', '')
        plan.persist()

    elif event_type == 'invoice.payment_failed':
        # If the payment fails or the customer does not have a valid payment method,
        # an invoice.payment_failed event is sent, the subscription becomes past_due.
        # Use this webhook to notify your user that their payment has
        # failed and to retrieve new card details.
        pass

    elif event_type == 'customer.subscription.deleted':
        # handle subscription cancelled automatically based
        # upon your subscription settings. Or if the user cancels it.
        pass

    return data
