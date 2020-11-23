from functools import wraps
from os import path, getenv
from socket import gethostbyname, error as SocketError, getaddrinfo, AF_INET6, AF_INET
from base64 import urlsafe_b64encode
from datetime import datetime
import re
import time
import logging
import socket
import ipaddress
import errno
import json
import requests
import boto3
import botocore
import OpenSSL
from bs4 import BeautifulSoup as bs
from dns import resolver, rdtypes
from dns.exception import DNSException
from urllib.parse import urlparse, urlencode
from dateutil.tz import tzlocal
from retry.api import retry
from passlib.hash import pbkdf2_sha256
from requests.status_codes import _codes
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.connectionpool import HTTPSConnectionPool
from requests.packages.urllib3.poolmanager import PoolManager
from requests.exceptions import ReadTimeout, ConnectTimeout, ConnectionError
from urllib3.poolmanager import SSL_KEYWORDS
from .log_manager import logger
from .config import config


class QueueData:
    def __init__(self, **kwargs):
        self.job_run_id = kwargs.get('job_run_id')
        self.queue_name = kwargs.get('queue_name')
        self.tracking_id = kwargs.get('tracking_id')
        self.scan_type = kwargs.get('scan_type')
        self.is_passive = kwargs.get('scan_type') == 'passive'
        self.is_active = kwargs.get('scan_type') == 'active'
        self.worker_id = kwargs.get('worker_id')
        self.service_node_id = kwargs.get('service_node_id')
        self.service_type_id = kwargs.get('service_type_id')
        self.service_type_name = kwargs.get('service_type_name')
        self.service_type_category = kwargs.get('service_type_category')
        self.job_uuid = kwargs.get('job_uuid')
        # amass, drill
        self.target = kwargs.get('target')
        # timings
        self.started_at = kwargs.get('started_at')
        self.completed_at = kwargs.get('completed_at')
        self.report_summary = kwargs.get('report_summary')

    def __str__(self):
        return json.dumps(self.__dict__, sort_keys=True, default=str)

    def __repr__(self):
        return str(self)

    def __iter__(self):
        yield from {
            'job_run_id': self.job_run_id,
            'target': self.target,
            'queue_name': self.queue_name,
            'tracking_id': self.tracking_id,
            'service_type': {
                'type_id': self.service_type_id,
                'name': self.service_type_name,
                'category': self.service_type_category
            }
        }.items()

class InspectedHTTPSConnectionPool(HTTPSConnectionPool):
    @property
    def inspector(self):
        return self._inspector

    @inspector.setter
    def inspector(self, inspector):
        self._inspector = inspector

    def _validate_conn(self, conn):
        req = super()._validate_conn(conn)
        if self.inspector:
            self.inspector(self.host, self.port, conn)

        return req

class InspectedPoolManager(PoolManager):
    @property
    def inspector(self):
        return self._inspector

    @inspector.setter
    def inspector(self, inspector):
        self._inspector = inspector

    def _new_pool(self, scheme, host, port, request_context=None):
        if scheme != 'https':
            return super()._new_pool(scheme, host, port)

        kwargs = self.connection_pool_kw.copy()
        if scheme == 'http':
            kwargs = self.connection_pool_kw.copy()
            for kword in SSL_KEYWORDS:
                kwargs.pop(kword, None)

        pool = InspectedHTTPSConnectionPool(host, port, **kwargs)
        pool.inspector = self.inspector
        return pool

class TLSInspectorAdapter(HTTPAdapter):
    def __init__(self, inspector):
        self._inspector = inspector
        super().__init__(max_retries=0)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = InspectedPoolManager(num_pools=connections, maxsize=maxsize, block=block, strict=True, **pool_kwargs)
        self.poolmanager.inspector = self._inspector

class SafeBrowsingInvalidApiKey(Exception):
    def __init__(self):
        Exception.__init__(self, "Invalid API key for Google Safe Browsing")


class SafeBrowsingWeirdError(Exception):
    def __init__(self, code, status, message, details):
        self.message = "%s(%i): %s (%s)" % (
            status,
            code,
            message,
            details
        )
        Exception.__init__(self, message)

class SafeBrowsing(object):
    def __init__(self, key):
        self.api_key = key

    def lookup_urls(self, urls, platforms=["ANY_PLATFORM"]):
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': config.http_proxy,
                'https': config.https_proxy
            }
        data = {
            "client": {
                "clientId":      "pysafe",
                "clientVersion": "0.1"
            },
            "threatInfo": {
                "threatTypes":
                    [
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "THREAT_TYPE_UNSPECIFIED",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ],
                "platformTypes": platforms,
                "threatEntryTypes": ["URL"],
                "threatEntries": [{'url': u} for u in urls]
            }
        }
        headers = {'Content-type': 'application/json'}

        r = requests.post(
                'https://safebrowsing.googleapis.com/v4/threatMatches:find',
                data=json.dumps(data),
                params={'key': self.api_key},
                headers=headers,
                proxies=proxies,
                timeout=3
        )
        if r.status_code == 200:
            # Return clean results
            if r.json() == {}:
                return dict([(u, {"malicious": False}) for u in urls])
            else:
                result = {}
                for url in urls:
                    # Get matches
                    matches = [match for match in r.json()['matches'] if match['threat']['url'] == url]
                    if len(matches) > 0:
                        result[url] = {
                            'malicious': True,
                            'platforms': list(set([b['platformType'] for b in matches])),
                            'threats': list(set([b['threatType'] for b in matches])),
                            'cache': min([b["cacheDuration"] for b in matches])
                        }
                    else:
                        result[url] = {"malicious": False}
                return result
        else:
            if r.status_code == 400:
                if r.json()['error']['message'] == 'API key not valid. Please pass a valid API key.':
                    raise SafeBrowsingInvalidApiKey()
                else:
                    raise SafeBrowsingWeirdError(
                        r.json()['error']['code'],
                        r.json()['error']['status'],
                        r.json()['error']['message'],
                        r.json()['error']['details']
                    )
            else:
                raise SafeBrowsingWeirdError(r.status_code, "", "", "")

    def lookup_url(self, url, platforms=["ANY_PLATFORM"]):
        """
        Online lookup of a single url
        """
        r = self.lookup_urls([url], platforms=platforms)
        return r[url]

class HTTPMetadata:
    HTTP_504 = 'Request Timeout'
    HTTP_599 = 'Network connect timeout error'
    SSL_DATE_FMT = r'%b %d %H:%M:%S %Y %Z'
    signature_algorithm = None
    negotiated_cipher = None
    protocol_version = None
    server_certificate = None
    server_key_size = None
    sha1_fingerprint = None
    pubkey_type = None
    headers = {}
    cookies = None
    elapsed_duration = 0
    code = None
    reason = None
    host = None
    port = None
    url = None
    method = None
    registered = None
    verification_hash = None
    dns_answer = None
    safe_browsing = {}
    phishtank = {}
    honey_score = None
    threat_score = None
    threat_type = None

    @property
    def metadata(self):
        return {
            'signature_algorithm': self.signature_algorithm,
            'negotiated_cipher': self.negotiated_cipher,
            'protocol_version': self.protocol_version,
            'server_certificate': self.server_certificate,
            'server_key_size': self.server_key_size,
            'sha1_fingerprint': self.sha1_fingerprint,
            'pubkey_type': self.pubkey_type,
            'headers': self.headers,
            'cookies': self.cookies,
            'elapsed_duration': str(self.elapsed_duration),
            'code': self.code,
            'reason': self.reason,
            'host': self.host,
            'port': self.port,
            'url': self.url,
            'method': self.method,
            'registered': self.registered,
            'verification_hash': self.verification_hash,
            'dns_answer': self.dns_answer,
            'safe_browsing': self.safe_browsing,
            'phishtank': self.phishtank,
            'honey_score': self.honey_score,
        }

    def __str__(self):
        return str(self.metadata)

    def __repr__(self):
        return str(self.metadata)

    def __init__(self, url: str, method: str = 'head'):
        target_url = url.replace(":80/", "/").replace(":443/", "/")
        self.url = target_url
        self.method = method
        parsed_uri = urlparse(self.url)
        self.host = parsed_uri.netloc

    def _connection_inspector(self, host, port, conn):
        self.host = host
        self.port = port
        self.negotiated_cipher, protocol, _ = conn.sock.cipher()
        self.protocol_version = conn.sock.version() or protocol
        self.server_certificate = conn.sock.getpeercert()
        der = conn.sock.getpeercert(True)
        certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der)
        self.signature_algorithm = certificate.get_signature_algorithm().decode('ascii')
        self.sha1_fingerprint = certificate.digest('sha1').decode('ascii')
        public_key = certificate.get_pubkey()
        self.pubkey_type = 'RSA' if public_key.type() == OpenSSL.crypto.TYPE_RSA else 'DSA'
        self.server_key_size = public_key.bits()

    def head(self):
        self.method = 'head'
        return self.fetch()

    def get(self):
        self.method = 'get'
        return self.fetch()

    @retry((SocketError), tries=5, delay=1.5, backoff=3)
    def fetch(self):
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': config.http_proxy,
                'https': config.https_proxy
            }
        session = requests.Session()
        if self.url.startswith('https'):
            session.mount(self.url, TLSInspectorAdapter(self._connection_inspector))
        method_callable = getattr(session, self.method)
        try:
            resp = method_callable(self.url,
                verify=self.url.startswith('https'),
                allow_redirects=False,
                proxies=proxies,
                timeout=3
            )
            self.elapsed_duration = resp.elapsed
            self.code = resp.status_code
            self.cookies = resp.cookies.get_dict(domain=self.host)
            titles = _codes[self.code]
            status, *_ = titles
            self.reason = resp.reason or status
            if not str(resp.status_code).startswith('2'):
                if resp.status_code == 403:
                    logger.warning(f"Forbidden {self.url}")
                    self.code = 403
                    self.reason = 'Forbidden'

                elif resp.status_code == 404:
                    logger.warning(f"Not Found {self.url}")
                    self.code = 404
                    self.reason = 'Not Found'
                else:
                    logger.error(f"Unexpected HTTP response code {resp.status_code} for URL {self.url}")
            for header, directive in resp.headers.lower_items():
                self.headers[header] = directive

        except ReadTimeout:
            self.code = 504
            self.reason = self.HTTP_504

        except ConnectTimeout:
            self.code = 599
            self.reason = self.HTTP_599

        except ConnectionError:
            self.code = 599
            self.reason = self.HTTP_599

        return self

    def get_scripts(self):
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': config.http_proxy,
                'https': config.https_proxy
            }
        res = requests.get(f'http://{self.host}',
            allow_redirects=True,
            proxies=proxies,
            timeout=3
        ).content
        soup = bs(res, 'html.parser')
        return [item['src'] for item in soup.select('script[src]')]

    def honeyscore_check(self):
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': config.http_proxy,
                'https': config.https_proxy
            }
        try:
            resp = requests.get(f'https://api.shodan.io/labs/honeyscore/{gethostbyname(self.host)}?key={config.honeyscore_key}',
                proxies=proxies,
                timeout=3
            )
            if resp.status_code != 200:
                return self
            self.honey_score = resp.text

        except IOError:
            pass
        except Exception as err:
            logger.exception(err)

        return self

    def safe_browsing_check(self):
        gcp_sb = SafeBrowsing(config.google_api_key)
        try:
            resp = gcp_sb.lookup_urls([
                f'http://{self.host}',
                f'https://{self.host}'
            ])
            for match in resp.get('matches', []):
                self.safe_browsing['threat_type'] = match.get('threatType')
                self.safe_browsing['platform_type'] = match.get('platformType')
                threat_entry_metadata = match.get('threatEntryMetadata')
                if threat_entry_metadata:
                    self.safe_browsing['threat_metadata'] = [
                        (entry.get('key'), entry.get('value')) for entry in threat_entry_metadata.get('entries', [])
                    ]
        except Exception as err:
            logger.exception(err)

        return self

    def phishtank_check(self):
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': config.http_proxy,
                'https': config.https_proxy
            }
        try:
            resp = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data=urlencode({
                    'url': urlsafe_b64encode(bytes(f'https://{self.host}', 'utf8')),
                    'format': 'json',
                    'app_key': config.phishtank_key
                }),
                headers={
                    'User-Agent': f'phishtank/{config.phishtank_username}',
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                proxies=proxies,
                timeout=3
            )
            self.phishtank = resp.json().get('results')

        except Exception as err:
            logger.exception(err)

        return self

    @staticmethod
    def dig(host, rdtype=16):
        res = None
        err = None
        try:
            dns_resolver = resolver.Resolver(configure=False)
            dns_resolver.lifetime = 5
            dns_resolver.nameservers = config.nameservers
            res = dns_resolver.query(host, rdtype=rdtype)

        except DNSException as ex:
            err = str(ex)
        except ConnectTimeout:
            err = 'DNS Timeout'

        return res, err

    def projecthoneypot(self):
        visitor_types = {
            0: 'Spider',
            1: 'Suspicious',
            2: 'Harvester',
            3: 'Suspicious & Harvester',
            4: 'Comment Spammer',
            5: 'Suspicious & Comment Spammer',
            6: 'Harvester & Comment Spammer',
            7: 'Suspicious & Harvester & Comment Spammer',
        }
        ip_list = set()
        try:
            for family, _, _, _, sock_addr in getaddrinfo(self.host, 443):
                if family == AF_INET6:
                    ip_list.add(sock_addr[0])
                if family == AF_INET:
                    ip_list.add(sock_addr[0])
            for family, _, _, _, sock_addr in getaddrinfo(self.host, 80):
                if family == AF_INET6:
                    ip_list.add(sock_addr[0])
                if family == AF_INET:
                    ip_list.add(sock_addr[0])

        except IOError as ex:
            logger.exception(ex)

        for addr in ip_list:
            reverse_octet = ipaddress.ip_address(addr).reverse_pointer.replace('.in-addr.arpa', '').replace('.ip6.arpa', '')
            query = f'{config.projecthoneypot_key}.{reverse_octet}.dnsbl.httpbl.org'
            logger.info(query)
            res, err = HTTPMetadata.dig(query, rdtype=1)
            if err:
                logger.error(err)
            if res is not None:
                dns_answer = str(res.response.answer[0][0])
                logger.info(f'projecthoneypot dns_answer {dns_answer}')
                check, last_activity_days, threat_score, visitor_type = dns_answer.split('.')
                if int(check) == 127:
                    self.threat_type = visitor_types[int(visitor_type)]
                    self.threat_score = int(threat_score)

        return self

    def verification_check(self):
        answers = []
        registered = True
        res, err = HTTPMetadata.dig(self.host)
        if res is not None:
            for rrdata in res.response.answer:
                self.dns_answer = str(rrdata)
                for rtype in rrdata:
                    if isinstance(rtype, rdtypes.txtbase.TXTBase):
                        answers.append(str(rtype))
        if err == 'DNS Timeout':
            registered = False

        if len(answers) > 0:
            for record in answers:
                if 'trivialsec=' not in record:
                    continue
                self.verification_hash = record.replace('"', '').split('=')[1]

        if err and 'None of DNS query names exist' in err:
            registered = False

        self.registered = registered

        return self

@retry((SocketError), tries=5, delay=1.5, backoff=3)
def download_file(remote_file: str, temp_name: str = None, temp_dir: str = '/tmp'):
    cached = False
    session = requests.Session()
    remote_file = remote_file.replace(":80/", "/").replace(":443/", "/")
    resp = session.head(remote_file, verify=remote_file.startswith('https'), allow_redirects=True, timeout=2)
    if not str(resp.status_code).startswith('2'):
        if resp.status_code == 403:
            logger.warning(f"Forbidden {remote_file}")
        elif resp.status_code == 404:
            logger.warning(f"Not Found {remote_file}")
            return None, cached
        else:
            logger.error(f"Unexpected HTTP response code {resp.status_code} for URL {remote_file}")
            return None, cached

    file_size = int(resp.headers.get('Content-Length', 0))
    dest_file = None
    if 'Content-disposition' in resp.headers:
        dest_file = resp.headers['Content-disposition'].replace('attachment;filename=', '').replace('attachment; filename=', '').replace('"', '', 2)
    if not dest_file:
        dest_file = temp_name
    if not dest_file:
        dest_file = urlsafe_b64encode(remote_file.encode('ascii')).decode('utf8')

    temp_path = f'{temp_dir}/{dest_file}'
    etag_path = f'{temp_path}.etag'
    if file_size > 0 and path.exists(temp_path):
        local_size = 0
        try:
            local_size = path.getsize(temp_path)
        except OSError as err:
            if err.errno == errno.ENOENT:
                pass
            else:
                raise
        if local_size == file_size:
            cached = True
            return temp_path, cached

    etag = resp.headers.get('ETag')
    if etag:
        local_etag = None
        if path.exists(etag_path):
            with open(etag_path, 'r') as handle:
                local_etag = handle.read()
        if local_etag == etag:
            cached = True
            return temp_path, cached

    resp = session.get(
        remote_file,
        verify=remote_file.startswith('https'),
        allow_redirects=True,
        headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15'}
    )
    text = resp.text
    with open(temp_path, 'w') as handle:
        handle.write(text)
    if etag:
        with open(etag_path, 'w') as handle:
            handle.write(etag)

    return temp_path, cached

@retry((SocketError), tries=5, delay=1.5, backoff=3, logger=logger)
def http_status(url: str)->(int, str):
    session = requests.Session()
    try:
        resp = session.head(url, verify=url.startswith('https'), allow_redirects=False, timeout=3)
        code = resp.status_code
        titles = _codes[code]
        status, *_ = titles
    except ReadTimeout:
        return 504, HTTPMetadata.HTTP_504

    return code, status

def check_domain_rules(domain_name: str):
    # TODO implement
    return True

def check_subdomain_rules(domain_name: str, sub_domain: str):
    return sub_domain.endswith(domain_name) and domain_name != sub_domain

def is_valid_ipv4_address(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton here, sorry
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address.count('.') == 3
    except socket.error:  # not a valid address
        return False

    return True

def is_valid_ipv6_address(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True

def cidr_address_list(cidr: str)->list:
    ret = []
    if '/' not in cidr:
        ret.append(cidr)
        return ret
    for ip_addr in ipaddress.IPv4Network(cidr, strict=False):
        if ip_addr.is_global:
            ret.append(str(ip_addr))

    return ret

def make_hash(string: str)->str:
    return ''.join(pbkdf2_sha256.using(rounds=1, salt_size=0).hash(string).split('$')[3:]).replace('/', '')

def hash_password(password):
    return pbkdf2_sha256.using(rounds=8000, salt_size=10).hash(password)

def check_encrypted_password(password, hashed):
    return pbkdf2_sha256.verify(password, hashed)

def control_timing_attacks(seconds: float):
    def deco(func):
        @wraps(func)
        def f_retry(*args, **kwargs):
            start = time.time()
            try:
                ret = func(*args, **kwargs)
            except Exception as err:
                ret = err
            end = time.time()
            elapsed_time = end - start
            logger.debug(f'elapsed_time {elapsed_time}')
            if elapsed_time < seconds:
                remaining = seconds - elapsed_time - 0.03
                time.sleep(remaining)
            return ret

        return f_retry
    return deco

def get_boto3_client(service: str, region_name: str, aws_profile: str = None, role_arn: str = None):
    boto_params = {
        'service_name': service,
        'region_name': region_name
    }
    session_params = {'region_name': region_name}
    if aws_profile:
        session_params['profile_name'] = aws_profile
    else:
        session_params['aws_access_key_id'] = getenv('AWS_ACCESS_KEY_ID')
        session_params['aws_secret_access_key'] = getenv('AWS_SECRET_ACCESS_KEY')

    base_session = boto3.session.Session(**session_params)

    if role_arn:
        base_session = assumed_role_session(role_arn, base_session)
    else:
        boto_params['aws_access_key_id'] = getenv('AWS_ACCESS_KEY_ID')
        boto_params['aws_secret_access_key'] = getenv('AWS_SECRET_ACCESS_KEY')

    return base_session.client(**boto_params)

def assumed_role_session(role_arn: str, base_session: botocore.session.Session, session_name: str = None, external_id: str = None):
    if isinstance(base_session, boto3.session.Session):
        base_session = base_session._session

    fetcher = botocore.credentials.AssumeRoleCredentialFetcher(
        client_creator=base_session.create_client,
        source_credentials=base_session.get_credentials(),
        role_arn=role_arn,
        extra_args={
            'RoleSessionName': session_name,
            'ExternalId': external_id
        }
    )
    creds = botocore.credentials.DeferredRefreshableCredentials(
        method='assume-role',
        refresh_using=fetcher.fetch_credentials,
        time_fetcher=lambda: datetime.now(tzlocal())
    )
    botocore_session = botocore.session.Session()
    botocore_session._credentials = creds

    return boto3.Session(botocore_session=botocore_session)

def default(func, ex: Exception, value):
    try:
        return func()
    except ex:
        return value

def extract_cve_id(search_string: str) -> str:
    cve = None
    try:
        matches = re.search(r'CVE-\d{4}-\d{4,7}', search_string)
        if matches:
            cve = matches.group()
    except Exception as ex:
        logger.exception(ex)
    return cve

def extract_cwe_id(search_string: str) -> str:
    cwe = None
    try:
        matches = re.search(r'CWE-\d{2,3}', search_string)
        if matches:
            cwe = matches.group()
    except Exception as ex:
        logger.exception(ex)
    return cwe