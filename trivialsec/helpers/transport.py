from os import path
from socket import gethostbyname, error as SocketError, getaddrinfo, AF_INET6, AF_INET
from base64 import urlsafe_b64encode
from urllib.parse import urlparse, urlencode, parse_qs
import ipaddress
import errno
import json
import requests
import OpenSSL
from bs4 import BeautifulSoup as bs
from dns import resolver, rdtypes
from dns.exception import DNSException
from retry.api import retry
from requests.status_codes import _codes
from requests.adapters import HTTPAdapter
from requests.exceptions import ReadTimeout, ConnectTimeout
from urllib3.exceptions import ConnectTimeoutError, SSLError, MaxRetryError
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.poolmanager import PoolManager, SSL_KEYWORDS
from .log_manager import logger
from .config import config


class InspectedHTTPSConnectionPool(HTTPSConnectionPool):
    @property
    def inspector(self):
        return self._inspector

    @inspector.setter
    def inspector(self, inspector):
        self._inspector = inspector

    def _validate_conn(self, conn):
        super()._validate_conn(conn)
        if self.inspector:
            self.inspector(self.host, self.port, conn)

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
            for keyword in SSL_KEYWORDS:
                kwargs.pop(keyword, None)

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

class SafeBrowsing:
    def __init__(self, key):
        self.api_key = key

    def lookup_urls(self, urls: list, platforms: list = None):
        if platforms is None:
            platforms = ["ANY_PLATFORM"]

        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': config.http_proxy,
                'https': config.https_proxy
            }
        data = {
            "client": {
                "clientId": "trivialsec-common",
                "clientVersion": config.app_version
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

        res = requests.post(
                'https://safebrowsing.googleapis.com/v4/threatMatches:find',
                data=json.dumps(data),
                params={'key': self.api_key},
                headers=headers,
                proxies=proxies,
                timeout=3
        )
        if res.status_code == 200:
            # Return clean results
            if res.json() == {}:
                return {u: {'malicious': False} for u in urls}
            result = {}
            for url in urls:
                # Get matches
                matches = [match for match in res.json()['matches'] if match['threat']['url'] == url]
                if len(matches) > 0:
                    result[url] = {
                        'malicious': True,
                        'platforms': { platform['platformType'] for platform in matches },
                        'threats': { threat['threatType'] for threat in matches },
                        'cache': min([b["cacheDuration"] for b in matches])
                    }
                else:
                    result[url] = {"malicious": False}
            return result
        if res.status_code == 400:
            if 'API key not valid' in res.json()['error']['message']:
                raise SafeBrowsingInvalidApiKey()
            raise SafeBrowsingWeirdError(
                res.json()['error']['code'],
                res.json()['error']['status'],
                res.json()['error']['message'],
                res.json()['error']['details']
            )
        raise SafeBrowsingWeirdError(res.status_code, "", "", "")

    def lookup_url(self, url: str, platforms: list = None):
        if platforms is None:
            platforms = ["ANY_PLATFORM"]
        return self.lookup_urls([url], platforms=platforms)[url]

class HTTPMetadata:
    HTTP_503 = 'Service Unavailable'
    HTTP_504 = 'Gateway Timeout'
    HTTP_598 = 'Network read timeout error'
    HTTP_599 = 'Network connect timeout error'
    TLS_ERROR = 'TLS handshake failure'
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
        try:
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

        except MaxRetryError:
            self.code = 503
            self.reason = self.HTTP_503

        except SSLError:
            self.code = 500
            self.reason = self.TLS_ERROR

        except ConnectionResetError:
            self.code = 503
            self.reason = self.HTTP_503

        except ConnectionError:
            self.code = 503
            self.reason = self.HTTP_503

        except ConnectTimeoutError:
            self.code = 598
            self.reason = self.HTTP_598

    def head(self, verify_tls: bool = False, allow_redirects: bool = False):
        self.method = 'head'
        return self.fetch(verify_tls=verify_tls, allow_redirects=allow_redirects)

    def get(self, verify_tls: bool = False, allow_redirects: bool = False):
        self.method = 'get'
        return self.fetch(verify_tls=verify_tls, allow_redirects=allow_redirects)

    def fetch(self, verify_tls: bool = False, allow_redirects: bool = False, http_timeout: int = 3):
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
                verify=verify_tls,
                allow_redirects=allow_redirects,
                proxies=proxies,
                timeout=http_timeout
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

        except MaxRetryError:
            self.code = 503
            self.reason = self.HTTP_503

        except SSLError:
            self.code = 500
            self.reason = self.TLS_ERROR

        except ConnectTimeout:
            self.code = 599
            self.reason = self.HTTP_599

        except ConnectionResetError:
            self.code = 503
            self.reason = self.HTTP_503

        except ConnectionError:
            self.code = 503
            self.reason = self.HTTP_503

        except ConnectTimeoutError:
            self.code = 598
            self.reason = self.HTTP_598

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
                check, last_activity_days, threat_score, visitor_type = dns_answer.split('.') # pylint: disable=unused-variable
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
                pass # no need to raise or handle this
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
        headers={'User-Agent': config.user_agent}
    )

    with open(temp_path, 'w') as handle:
        handle.write(resp.text)
    if etag:
        with open(etag_path, 'w') as handle:
            handle.write(etag)

    return temp_path, cached

@retry((SocketError), tries=5, delay=1.5, backoff=3, logger=logger)
def http_status(url: str):
    session = requests.Session()
    try:
        resp = session.head(url, verify=url.startswith('https'), allow_redirects=False, timeout=3)
        code = resp.status_code
        titles = _codes[code]
        status, *_ = titles
    except ReadTimeout:
        return 504, HTTPMetadata.HTTP_504

    return code, status

def request_from_raw(raw: str, encoding: str = 'unicode-escape') -> dict:
    body = parse_qs(raw.decode(encoding))
    data = {}
    for _, key in enumerate(body):
        if isinstance(body[key], list) and len(body[key]) == 1:
            val = body[key][0]
        else:
            val = body[key]
        ktype = None
        if key[-2:] == '[]':
            ktype = list
        if key[-1:] == ']' and '[' in key:
            ktype = dict
        if ktype:
            new_key = key[:key.find('[')]
            if new_key not in data:
                if ktype == list:
                    data[new_key] = []
                    data[new_key].append(val)
            elif ktype == list:
                data[new_key].append(val)
            if ktype == dict:
                d_key = key[key.find('[')+1:key.find(']')]
                if new_key not in data:
                    data[new_key] = {}
                data[new_key][d_key] = val
        else:
            data[key] = val

    return data
