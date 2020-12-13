from os import getenv, path, getcwd
import sys
import logging
import subprocess
import yaml
import boto3
from botocore.exceptions import ClientError, ConnectionClosedError, ReadTimeoutError, ConnectTimeoutError, CapacityNotAvailableError
from retry.api import retry


class Config:
    user_agent: str = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15'
    config_file: str = getenv('CONFIG_FILE', 'config.yaml')
    def __init__(self):
        self.config_path: str = self.config_file if self.config_file.startswith('/') else path.realpath(path.join(getcwd(), self.config_file))
        try:
            with open(self.config_path) as stream:
                conf: dict = yaml.safe_load(stream)
            app_conf: dict = conf.get('app', dict())
            self.app_version = app_conf.get('version')
            self.app_env = app_conf.get('env', 'Dev')
            self.app_name = app_conf.get('app_name', 'trivialsec')
            self.http_proxy = app_conf.get('http_proxy')
            self.https_proxy = app_conf.get('https_proxy')
            self.session_expiry_minutes = app_conf.get('session_expiry_minutes', 1440)
            self.session_cookie_name = app_conf.get('session_cookie_name', 'trivialsec')
            self.mysql: dict = conf.get('mysql', dict())
            self.redis: dict = conf.get('redis', dict())
            self.aws: dict = conf.get('aws', dict())
            self.frontend: dict = app_conf.get('frontend', dict())
            self.backend: dict = app_conf.get('backend', dict())
            self.cve: dict = app_conf.get('cve', dict())
            self.amass: dict = conf.get('amass', dict())
            self.sendgrid: dict = conf.get('sendgrid', dict())
            self.stripe: dict = conf.get('stripe', dict())
            self.nmap: dict = app_conf.get('nmap', dict())

            app_log_level: str = app_conf.get('log_level', getenv('LOG_LEVEL', default='WARNING'))
            proc = subprocess.run('cat /etc/hostname', shell=True, capture_output=True, check=True)
            node_id: str = proc.stdout.decode('utf-8').strip()
            err = proc.stderr.decode('utf-8')
            if err or not node_id:
                raise OSError(f'/etc/hostname could not be used\ngot node_id {node_id}\n{err}')

        except Exception as ex:
            print(ex)
            sys.exit(1)

        self.node_id: str = node_id
        self.log_level: int = app_log_level if isinstance(app_log_level, int) else logging._nameToLevel.get(app_log_level)
        self.log_file: str = app_conf.get('log_file', '/tmp/application.log')
        self.nameservers: list = list(set(app_conf.get('nameservers', list())))
        self.external_dsn_provider: str = self.nameservers[0]
        self.queue_wait_timeout: int = app_conf.get('queue_wait_timeout', 5)
        self.mysql['password']: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/MysqlPassword')
        self.session_secret_key: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/SessionSecretKey')
        self.recaptcha_secret_key: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/RecaptchaSecretKey')
        self.recaptcha_site_key: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/RecaptchaSiteKey')
        self.sendgrid_api_key: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/SendGridApiKey')
        self.stripe_publishable_key: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/StripePublishableKey')
        self.stripe_secret_key: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/StripeSecretKey')
        self.stripe_webhook_secret: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/StripeWebhookSecret', default='whsec_jZhj4vRAWZotw2hdgl118i7Xevn1GZ3G')
        self.google_api_key: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/GoogleAPIKey')
        self.phishtank_key: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/PhishtankKey')
        self.phishtank_username: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/PhishtankUsername')
        self.honeyscore_key: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/HoneyScoreKey')
        self.projecthoneypot_key: str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/ProjectHoneypot')

    @retry((ConnectionClosedError, ReadTimeoutError, ConnectTimeoutError, CapacityNotAvailableError), tries=5, delay=1.5, backoff=3)
    def ssm_secret(self, parameter: str, default=None, **kwargs) -> str:
        session = boto3.session.Session()
        client = session.client(
            service_name='ssm',
            region_name=self.aws.get('region_name', 'ap-southeast-2'),
        )
        response = None
        value = default
        try:
            response = client.get_parameter(
                Name=parameter, **kwargs
            )
        except ClientError as err:
            if err.response['Error']['Code'] == 'ResourceNotFoundException':
                print(f"The requested secret {parameter} was not found")
            elif err.response['Error']['Code'] == 'InvalidRequestException':
                print("The request was invalid due to:", err)
            elif err.response['Error']['Code'] == 'InvalidParameterException':
                print("The request had invalid params:", err)

        if response and 'Parameter' in response:
            value = response['Parameter'].get('Value')

        return value

    def get_app(self)->dict:
        return {
            'host_scheme': self.frontend.get('site_scheme'),
            'host_domain': self.frontend.get('site_domain'),
            'host_url': f"{self.frontend.get('site_scheme')}{self.frontend.get('site_domain')}",
            'socket_scheme': self.frontend.get('socket_scheme'),
            'socket_domain': self.frontend.get('socket_domain'),
            'socket_url': f"{self.frontend.get('socket_scheme')}{self.frontend.get('socket_domain')}"
        }

config = Config()
