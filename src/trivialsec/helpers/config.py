from os import getenv
import sys
import logging
import subprocess
from pprint import pprint # logger is not configured yet, just print
from io import StringIO
from datetime import timedelta, datetime
from dateutil.tz import tzlocal
import yaml
import boto3
import redis
from dotenv import dotenv_values
from botocore.credentials import AssumeRoleCredentialFetcher, DeferredRefreshableCredentials
from botocore.exceptions import ClientError, ConnectionClosedError, ReadTimeoutError, ConnectTimeoutError, CapacityNotAvailableError
from retry.api import retry


__module__ = 'trivialsec.helpers.config'
dotenv = dotenv_values(".env")

class Config:
    redis_client = None
    user_agent :str = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15'

    def __init__(self):
        self.app_env = dotenv.get('APP_ENV')
        if self.app_env is None:
            self.app_env = getenv('APP_ENV', 'Dev')
        self.app_name = dotenv.get('APP_NAME')
        if self.app_name is None:
            self.app_name = getenv('APP_NAME', 'trivialsec')
        self.aws_default_region = dotenv.get('AWS_REGION')
        if self.aws_default_region is None:
            self.aws_default_region = getenv('AWS_REGION', 'ap-southeast-2')
        self._log_level = dotenv.get('LOG_LEVEL')
        if self._log_level is None:
            self._log_level = getenv('LOG_LEVEL', 'WARNING')
        aws_access_key_id = dotenv.get('AWS_ACCESS_KEY_ID')
        if aws_access_key_id is None:
            aws_access_key_id = getenv('AWS_ACCESS_KEY_ID')
        aws_secret_access_key = dotenv.get('AWS_SECRET_ACCESS_KEY')
        if aws_secret_access_key is None:
            aws_secret_access_key = getenv('AWS_SECRET_ACCESS_KEY')
        aws_session_token = dotenv.get('AWS_SESSION_TOKEN')
        if aws_session_token is None:
            aws_session_token = getenv('AWS_SESSION_TOKEN')
        self.boto3_session = boto3.session.Session(
            region_name=self.aws_default_region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
        )
        aws_role_arn = dotenv.get('AWS_ROLE_ARN')
        if aws_role_arn is None:
            aws_role_arn = getenv('AWS_ROLE_ARN')
        if aws_role_arn is not None:
            session_name = 'trivialsec'
            aws_role_external_id = dotenv.get('AWS_ROLE_EXTERNAL_ID')
            if aws_role_external_id is None:
                aws_role_external_id = getenv('AWS_ROLE_EXTERNAL_ID')
            credentials = DeferredRefreshableCredentials(
                method='assume-role',
                refresh_using=AssumeRoleCredentialFetcher(
                    client_creator=self.boto3_session._session.create_client, # pylint: disable=protected-access
                    source_credentials=self.boto3_session._session.get_credentials(), # pylint: disable=protected-access
                    role_arn=aws_role_arn,
                    extra_args={
                        'RoleSessionName': session_name,
                        'ExternalId': aws_role_external_id
                    }
                ).fetch_credentials,
                time_fetcher=lambda: datetime.now(tzlocal())
            )
            self.boto3_session._session._credentials = credentials # pylint: disable=protected-access
        self.configure()

    def configure(self):
        config_key = f'/{self.app_env}/Deploy/{self.app_name}/app_config'
        try:
            main_raw :str = self.ssm_secret(config_key, skip_cache=True)
            main_conf :dict = yaml.safe_load(StringIO(main_raw))
            amass_raw :str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/amass_config', skip_cache=True)
            amass_conf :dict = yaml.safe_load(StringIO(amass_raw))
            routes_raw :str = self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/routes_config', skip_cache=True)
            routes_conf :dict = yaml.safe_load(StringIO(routes_raw))

            self.redis :dict = main_conf.get('redis', dict())
            self.redis_client :redis.Redis = redis.Redis(host=self.redis.get('host'), ssl=bool(self.redis.get('ssl')))

            self.log_level: int = self._log_level if isinstance(self._log_level, int) else logging._nameToLevel.get(self._log_level) # pylint: disable=protected-access
            proc = subprocess.run('cat /etc/hostname', shell=True, capture_output=True, check=True)
            node_id :str = proc.stdout.decode('utf-8').strip()
            err = proc.stderr.decode('utf-8')
            if err or not node_id:
                raise OSError(f'/etc/hostname could not be used\ngot node_id {node_id}\n{err}')
            self.node_id :str = node_id
            self.app_version = main_conf.get('version')
            self.http_proxy = main_conf.get('http_proxy')
            self.https_proxy = main_conf.get('https_proxy')
            self.authz_expiry_seconds = main_conf.get('authz_expiry_seconds', 3600)
            self.session_expiry_minutes = main_conf.get('session_expiry_minutes', 1440)
            self.session_cookie_name = main_conf.get('session_cookie_name', 'trivialsec')
            self.mysql :dict = main_conf.get('mysql', dict())
            self.elasticsearch :dict = main_conf.get('elasticsearch', dict())
            self.aws :dict = main_conf.get('aws', dict())
            self.assets :dict = main_conf.get('assets', dict())
            self.website :dict = main_conf.get('website', dict())
            self.appserver :dict = main_conf.get('appserver', dict())
            self.public_api :dict = main_conf.get('public-api', dict())
            self.push :dict = main_conf.get('push', dict())
            self.sendgrid :dict = main_conf.get('sendgrid', dict())
            self.stripe :dict = main_conf.get('stripe', dict())
            self.nameservers :list = list(set(main_conf.get('nameservers', list())))
            self.queue_wait_timeout: int = main_conf.get('queue_wait_timeout', 5)
            self.nmap :dict = main_conf.get('nmap', dict())
            self.amass :dict = amass_conf.get('amass', dict())
            self.public_endpoints :list = list(routes_conf.get('public_endpoints', list()))
            self.require_authz :list = list(routes_conf.get('require_authz', list()))

        except Exception as ex:
            pprint(ex)
            sys.exit(1)

    @property
    def elasticsearch_password(self):
        return self.ssm_secret(f'/{self.app_env}/Deploy/{self.app_name}/elasticsearch_password', WithDecryption=True)

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
    def ssm_secret(self, parameter :str, default=None, skip_cache :bool = False, **kwargs) -> str:
        if skip_cache is not True:
            redis_value = self._get_from_redis(parameter)
            if redis_value is not None:
                return redis_value
        response = None
        value = default
        try:
            ssm_client = self.boto3_session.client(service_name='ssm')
            response = ssm_client.get_parameter(
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

        if skip_cache is not True and value is not None:
            self._save_to_redis(parameter, value)

        return value

    def get_app(self)->dict:
        default_scheme = 'https://'
        default_host = 'https://'
        ret = {
            'asset_scheme': self.assets.get('scheme', default_scheme),
            'asset_domain': self.assets.get('host', default_host),
            'site_scheme': self.website.get('scheme',default_scheme),
            'site_domain': self.website.get('host', default_host),
            'app_scheme': self.appserver.get('scheme', default_scheme),
            'app_domain': self.appserver.get('host', default_host),
            'api_scheme': self.public_api.get('scheme', default_scheme),
            'api_domain': self.public_api.get('host', default_host),
            'socket_scheme': self.push.get('scheme', 'wss://'),
            'socket_domain': self.push.get('host', default_host),
        }
        ret['asset_url'] = ret['asset_scheme'] + ret['asset_domain']
        ret['site_url'] = ret['site_scheme'] + ret['site_domain']
        ret['app_url'] = ret['app_scheme'] + ret['app_domain']
        ret['api_url'] = ret['api_scheme'] + ret['api_domain']
        ret['socket_url'] = ret['socket_scheme'] + ret['socket_domain']
        return ret

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
