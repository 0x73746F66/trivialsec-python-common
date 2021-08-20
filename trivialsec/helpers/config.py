from os import getenv
import sys
import logging
import subprocess
from io import StringIO
from datetime import timedelta
import yaml
import boto3
import redis
from botocore.exceptions import ClientError, ConnectionClosedError, ReadTimeoutError, ConnectTimeoutError, CapacityNotAvailableError
from retry.api import retry


__module__ = 'trivialsec.helpers.config'

class Config:
    redis_client = None
    user_agent :str = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15'
    app_env :str = getenv('APP_ENV', 'Dev')
    app_name :str = getenv('APP_NAME', 'trivialsec')

    def __init__(self):
        self.configure()

    def configure(self):
        try:
            raw_yaml :str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/app_config')
            conf :dict = yaml.safe_load(StringIO(raw_yaml))
            self.redis :dict = conf.get('redis', dict())
            self.redis_client :redis.Redis = redis.Redis(host=self.redis.get('host'), ssl=bool(self.redis.get('ssl')))
            app_conf :dict = conf.get('app', dict())
            app_log_level :str = app_conf.get('log_level', getenv('LOG_LEVEL', default='WARNING'))
            self.log_level: int = app_log_level if isinstance(app_log_level, int) else logging._nameToLevel.get(app_log_level) # pylint: disable=protected-access
            proc = subprocess.run('cat /etc/hostname', shell=True, capture_output=True, check=True)
            node_id :str = proc.stdout.decode('utf-8').strip()
            err = proc.stderr.decode('utf-8')
            if err or not node_id:
                raise OSError(f'/etc/hostname could not be used\ngot node_id {node_id}\n{err}')
            self.node_id :str = node_id

        except Exception as ex:
            print(ex)
            sys.exit(1)

        self.app_version = app_conf.get('version')
        self.app_env = app_conf.get('env', self.app_env)
        self.app_name = app_conf.get('app_name', self.app_name)
        self.http_proxy = app_conf.get('http_proxy')
        self.https_proxy = app_conf.get('https_proxy')
        self.authz_expiry_seconds = app_conf.get('authz_expiry_seconds', 3600)
        self.session_expiry_minutes = app_conf.get('session_expiry_minutes', 1440)
        self.session_cookie_name = app_conf.get('session_cookie_name', 'trivialsec')
        self.mysql :dict = conf.get('mysql', dict())
        self.aws :dict = conf.get('aws', dict())
        self.frontend :dict = app_conf.get('frontend', dict())
        self.cve :dict = app_conf.get('cve', dict())
        self.amass :dict = conf.get('amass', dict())
        self.sendgrid :dict = conf.get('sendgrid', dict())
        self.stripe :dict = conf.get('stripe', dict())
        self.nmap :dict = app_conf.get('nmap', dict())
        self.nameservers :list = list(set(app_conf.get('nameservers', list())))
        self.external_dsn_provider :str = self.nameservers[0]
        self.queue_wait_timeout: int = app_conf.get('queue_wait_timeout', 5)
        self.public_endpoints :list = list(app_conf.get('public_endpoints', list()))
        self.require_authz :list = list(app_conf.get('require_authz', list()))

    @property
    def mysql_main_password(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/mysql_main_password', WithDecryption=True)

    @property
    def mysql_replica_password(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/mysql_replica_password', WithDecryption=True)

    @property
    def session_secret_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/session_secret_key', WithDecryption=True)

    @property
    def recaptcha_secret_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/recaptcha_secret_key', WithDecryption=True)

    @property
    def sendgrid_api_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/sendgrid_api_key', WithDecryption=True)

    @property
    def stripe_secret_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/stripe_secret_key', WithDecryption=True)

    @property
    def stripe_webhook_secret(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/stripe_webhook_secret', WithDecryption=True)

    @property
    def google_api_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/google_api_key', WithDecryption=True)

    @property
    def phishtank_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/phishtank_key', WithDecryption=True)

    @property
    def honeyscore_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/honeyscore_key', WithDecryption=True)

    @property
    def projecthoneypot_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/projecthoneypot_key', WithDecryption=True)

    @property
    def whoisxmlapi_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/whoisxmlapi_key', WithDecryption=True)

    @property
    def phishtank_username(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/phishtank_username')

    @property
    def stripe_publishable_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/stripe_publishable_key')

    @property
    def recaptcha_site_key(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/recaptcha_site_key')

    @retry((ConnectionClosedError, ReadTimeoutError, ConnectTimeoutError, CapacityNotAvailableError), tries=5, delay=1.5, backoff=3)
    def ssm_secret(self, parameter :str, default=None, **kwargs) -> str:
        redis_value = self._get_from_redis(parameter)
        if redis_value is not None:
            return redis_value
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

        if value is not None:
            self._save_to_redis(parameter, value)

        return value

    def get_app(self)->dict:
        return {
            'asset_scheme': self.frontend.get('asset_scheme'),
            'asset_domain': self.frontend.get('asset_domain'),
            'asset_url': f"{self.frontend.get('asset_scheme')}{self.frontend.get('asset_domain')}",
            'site_scheme': self.frontend.get('site_scheme'),
            'site_domain': self.frontend.get('site_domain'),
            'site_url': f"{self.frontend.get('site_scheme')}{self.frontend.get('site_domain')}",
            'app_scheme': self.frontend.get('app_scheme'),
            'app_domain': self.frontend.get('app_domain'),
            'app_url': f"{self.frontend.get('app_scheme')}{self.frontend.get('app_domain')}",
            'api_scheme': self.frontend.get('api_scheme'),
            'api_domain': self.frontend.get('api_domain'),
            'api_url': f"{self.frontend.get('api_scheme')}{self.frontend.get('api_domain')}",
            'socket_scheme': self.frontend.get('socket_scheme'),
            'socket_domain': self.frontend.get('socket_domain'),
            'socket_url': f"{self.frontend.get('socket_scheme')}{self.frontend.get('socket_domain')}",
        }

    def _get_from_redis(self, cache_key :str):
        redis_value = None
        if isinstance(cache_key, str):
            redis_value = self.redis_client.get(f'{self.app_version}{cache_key}')

        if redis_value is not None:
            return redis_value.decode()

        return None

    def _save_to_redis(self, cache_key :str, result :str):
        cache_ttl = timedelta(seconds=int(self.redis.get('ttl', 300)))
        return self.redis_client.set(f'{self.app_version}{cache_key}', result, ex=cache_ttl)

config = Config()
