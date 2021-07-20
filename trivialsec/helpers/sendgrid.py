import requests
from sendgrid import SendGridAPIClient
from trivialsec.helpers.config import config
from gunicorn.glogging import logging


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers.sendgrid'

def send_email(subject :str, template :str, data :dict, recipient :str, group :str = 'notifications', sender :str = 'support@trivialsec.com'):
    sendgrid = SendGridAPIClient(config.sendgrid_api_key)
    tmp_url = sendgrid.client.mail.send._build_url(query_params={}) # pylint: disable=protected-access
    req_body = {
        'subject': subject,
        'from': {'email': sender},
        'template_id': config.sendgrid.get('templates').get(template),
        'asm': {
            'group_id': config.sendgrid.get('groups').get(group)
        },
        'personalizations': [
            {
                'dynamic_template_data': {**data, **{'email': recipient}},
                'to': [
                    {
                        'email': recipient
                    }
                ]
            }
        ]
    }
    # https://github.com/sendgrid/sendgrid-python/issues/409
    proxies = None
    if config.http_proxy or config.https_proxy:
        proxies = {
            'http': config.http_proxy,
            'https': config.https_proxy
        }

    res = requests.post(url=tmp_url,
        json=req_body,
        headers=sendgrid.client.request_headers,
        proxies=proxies,
        timeout=10
    )
    logger.debug(res.__dict__)
    return res

def upsert_contact(recipient_email :str, list_name :str = 'subscribers'):
    sendgrid = SendGridAPIClient(config.sendgrid_api_key)
    # https://github.com/sendgrid/sendgrid-python/issues/409
    proxies = None
    if config.http_proxy or config.https_proxy:
        proxies = {
            'http': config.http_proxy,
            'https': config.https_proxy
        }

    res = requests.put(url='https://api.sendgrid.com/v3/marketing/contacts',
        json={
            "list_ids": [
                config.sendgrid.get('lists').get(list_name)
            ],
            "contacts": [{
                "email": recipient_email
            }]
        },
        headers=sendgrid.client.request_headers,
        proxies=proxies,
        timeout=10
    )
    logger.debug(res.__dict__)
    return res
