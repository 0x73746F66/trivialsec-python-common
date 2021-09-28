import ipaddress
import re
import errno
import json
import ssl
from pathlib import Path
from os import path
from socket import socket, error as SocketError, getaddrinfo, AF_INET6, AF_INET, SOCK_STREAM
from base64 import urlsafe_b64encode
from urllib.parse import urlparse, parse_qs
from cryptography import x509
from OpenSSL.crypto import load_certificate, dump_certificate, X509, X509Name, TYPE_RSA, FILETYPE_ASN1, FILETYPE_PEM
from ssl import create_default_context, SSLCertVerificationError, Purpose, CertificateError
from datetime import datetime
import requests
from certvalidator import CertificateValidator, ValidationContext
from certvalidator.errors import PathValidationError, RevokedError, InvalidCertificateError
from bs4 import BeautifulSoup as bs
from dns import query, zone, resolver, rdtypes
from dns.exception import DNSException
from aslookup import get_as_data
from aslookup.exceptions import NoASDataError, NonroutableAddressError, AddressFormatError
from retry.api import retry
from requests.status_codes import _codes
from requests.adapters import HTTPAdapter
from requests.exceptions import ReadTimeout, ConnectTimeout
from urllib3.exceptions import ConnectTimeoutError, SSLError, MaxRetryError, NewConnectionError
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.poolmanager import PoolManager, SSL_KEYWORDS
from gunicorn.glogging import logging
from .config import config
from . import is_valid_ipv4_address


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers.transport'
HTTP_503 = 'Service Unavailable'
HTTP_504 = 'Gateway Timeout'
HTTP_598 = 'Network read timeout error'
HTTP_599 = 'Network connect timeout error'
TLS_ERROR = 'TLS handshake failure'
SSL_DATE_FMT = r'%b %d %H:%M:%S %Y %Z'
X509_DATE_FMT = r'%Y%m%d%H%M%SZ'
SEMVER_REGEX = r'\d+(=?\.(\d+(=?\.(\d+)*)*)*)*'
DOCSTRING_REGEX = r"\/\*([\s\S]*?)\*\/"

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

    def lookup_urls(self, urls :list, platforms :list = None):
        if platforms is None:
            platforms = ["ANY_PLATFORM"]

        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': f'http://{config.http_proxy}',
                'https': f'https://{config.https_proxy}'
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

    def lookup_url(self, url :str, platforms :list = None):
        if platforms is None:
            platforms = ["ANY_PLATFORM"]
        return self.lookup_urls([url], platforms=platforms)[url]

class Metadata:
    def __init__(self, url :str, method :str = 'head'):
        self._peer_certificate_chain = []
        self._content = None
        target_url = url.replace(":80/", "/").replace(":443/", "/")
        self.url = target_url
        self.method = method
        parsed_uri = urlparse(self.url)
        self.host = parsed_uri.netloc
        self.signature_algorithm = None
        self.negotiated_cipher = None
        self.protocol_version = None
        self.server_certificate = None
        self.server_key_size = None
        self.sha1_fingerprint = None
        self.pubkey_type = None
        self.certificate_is_self_signed = None
        self.certificate_verify_message = None
        self.certificate_serial_number = None
        self.certificate_issuer = None
        self.certificate_issuer_country = None
        self.certificate_not_before = None
        self.certificate_not_after = None
        self.certificate_issued_desc = None
        self.certificate_expiry_desc = None
        self.certificate_san = []
        self.headers = {}
        self.application_banner = None
        self.server_banner = None
        self.application_proxy = None
        self.cookies = None
        self.elapsed_duration = 0
        self.code = None
        self.reason = None
        self.redirect_location = None
        self.port = None
        self.verification_hash = None
        self.txt_verification = False
        self.dns_answer = None
        self.html_last_checked = None
        self.html_size = None
        self.javascript = []
        self.html_title = None
        self.programs = []
        self.asn_data = []
        self.certificate_chain = []
        self.certificate_chain_revoked = None
        self.certificate_chain_valid = None
        self.certificate_chain_trust = None
        self.certificate_chain_validation_result = None

    def _connection_inspector(self, host, port, conn):
        self.host = host
        self.port = port
        try:
            der = conn.sock.getpeercert(True)
            self.negotiated_cipher, protocol, _ = conn.sock.cipher()
            self.protocol_version = conn.sock.version() or protocol

        except CertificateError:
            self.code = 500
            self.reason = TLS_ERROR
        except MaxRetryError:
            self.code = 503
            self.reason = HTTP_503
        except SSLError:
            self.code = 500
            self.reason = TLS_ERROR
        except ConnectionResetError:
            self.code = 503
            self.reason = HTTP_503
        except NewConnectionError:
            self.code = 503
            self.reason = HTTP_503
        except ConnectionError:
            self.code = 503
            self.reason = HTTP_503
        except ConnectTimeoutError:
            self.code = 598
            self.reason = HTTP_598
        except SocketError:
            self.code = 503
            self.reason = HTTP_503

        self._peer_certificate_chain.append(der)
        self.server_certificate = load_certificate(FILETYPE_ASN1, der)
        self.signature_algorithm = self.server_certificate.get_signature_algorithm().decode('ascii')
        self.sha1_fingerprint = self.server_certificate.digest('sha1').decode('ascii')
        public_key = self.server_certificate.get_pubkey()
        self.pubkey_type = 'RSA' if public_key.type() == TYPE_RSA else 'DSA'
        self.server_key_size = public_key.bits()
        crypto_x509 = self.server_certificate.to_cryptography()
        self.certificate_san = crypto_x509.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)

        # TODO perhaps remove certvalidator, consider once merged: https://github.com/pyca/cryptography/issues/2381
        try:
            ctx = ValidationContext(allow_fetching=True, revocation_mode='hard-fail', weak_hash_algos=set(["md2", "md5", "sha1"]))
            validator = CertificateValidator(der, validation_context=ctx)
            validator.validate_usage(
                key_usage=set(['digital_signature', 'crl_sign']),
                extended_key_usage=set(['ocsp_signing']),
            )
        except RevokedError as ex:
            self.certificate_chain_revoked = True
            self.certificate_chain_validation_result = str(ex)
        except InvalidCertificateError as ex:
            self.certificate_chain_valid = False
            self.certificate_chain_validation_result = str(ex)
        except PathValidationError as ex:
            self.certificate_chain_trust = False
            self.certificate_chain_validation_result = str(ex)

        if self.certificate_chain_validation_result is None:
            self.certificate_chain_revoked = False
            self.certificate_chain_trust = True
            self.certificate_chain_valid = True
            self.certificate_chain_validation_result = 'Validated CRL, OSCP, and digital signatures'

    def head(self, verify_tls :bool = False, allow_redirects :bool = False):
        self.method = 'head'
        return self.fetch(verify_tls=verify_tls, allow_redirects=allow_redirects)

    def get(self, verify_tls :bool = False, allow_redirects :bool = False):
        self.method = 'get'
        return self.fetch(verify_tls=verify_tls, allow_redirects=allow_redirects)

    def fetch(self, verify_tls :bool = False, allow_redirects :bool = False, http_timeout: int = 3):
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': f'http://{config.http_proxy}',
                'https': f'https://{config.https_proxy}'
            }
        try:
            session = requests.Session()
            if self.url.startswith('https'):
                session.mount(self.url, TLSInspectorAdapter(self._connection_inspector))
            method_callable = getattr(session, self.method)
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
            if self.method.lower() not in ['head', 'options', 'delete']:
                self._content = resp.content

            for header, directive in resp.headers.items():
                header_name = header.lower()
                self.headers[header_name] = directive
                program_name, program_version = extract_server_version(directive)
                if header_name == 'x-powered-by':
                    self.application_banner = directive
                    self.programs.append({
                        'name': program_name,
                        'version': program_version,
                        'category': 'application-server',
                    })
                if header_name == 'server':
                    self.server_banner = directive
                    self.programs.append({
                        'name': program_name,
                        'version': program_version,
                        'category': 'web-server',
                    })
                if header_name == 'via':
                    self.application_proxy = directive
                    self.programs.append({
                        'name': program_name,
                        'version': program_version,
                        'category': 'proxy-cache',
                    })

            if not str(self.code).startswith('2'):
                if self.code == 403:
                    logger.warning(f"Forbidden {self.url}")
                    self.code = 403
                    self.reason = 'Forbidden'
                elif self.code in [301, 302]:
                    self.redirect_location = self.headers.get('location')
                elif self.code == 404:
                    logger.warning(f"Not Found {self.url}")
                    self.code = 404
                    self.reason = 'Not Found'
                elif self.code in [502, 503, 401]:
                    logger.warning(f"HTTP response code {self.code} for URL {self.url}")
                else:
                    logger.warning(f"Unexpected HTTP response code {self.code} for URL {self.url}")

        except ReadTimeout:
            self.code = 504
            self.reason = HTTP_504
        except MaxRetryError:
            self.code = 503
            self.reason = HTTP_503
        except SSLError:
            self.code = 500
            self.reason = TLS_ERROR
        except ConnectTimeout:
            self.code = 599
            self.reason = HTTP_599
        except ConnectionResetError:
            self.code = 503
            self.reason = HTTP_503
        except NewConnectionError:
            self.code = 503
            self.reason = HTTP_503
        except ConnectionError:
            self.code = 503
            self.reason = HTTP_503
        except ConnectTimeoutError:
            self.code = 598
            self.reason = HTTP_598
        except SocketError:
            self.code = 503
            self.reason = HTTP_503

        # TODO waiting for merge https://github.com/python/cpython/pull/17938
        if isinstance(self._peer_certificate_chain, list):
            for pos, der in enumerate(self._peer_certificate_chain):
                cert = load_certificate(FILETYPE_ASN1, der)
                pem_filepath = f'/tmp/{self.host}-{pos}.pem'
                Path(pem_filepath).write_bytes(dump_certificate(FILETYPE_PEM, cert))
                try:
                    cert_dict = ssl._ssl._test_decode_cert(pem_filepath) # pylint: disable=protected-access
                    self.certificate_chain.append(cert_dict)
                except Exception as ex:
                    logger.exception(ex)

        self.certificate_is_self_signed = False
        try:
            ctx1 = create_default_context(purpose=Purpose.CLIENT_AUTH)
            with ctx1.wrap_socket(socket(), server_hostname=self.host) as sock:
                sock.connect((self.host, 443))

        except SSLCertVerificationError as err:
            if 'self signed certificate' in err.verify_message:
                self.certificate_is_self_signed = True
            self.certificate_verify_message = str(err)

        if isinstance(self.server_certificate, X509):
            self.certificate_serial_number = str(self.server_certificate.get_serial_number())
            issuer: X509Name = self.server_certificate.get_issuer()
            self.certificate_issuer = issuer.commonName
            self.certificate_issuer_country = issuer.countryName
            not_before = datetime.strptime(self.server_certificate.get_notBefore().decode('ascii'), X509_DATE_FMT)
            not_after = datetime.strptime(self.server_certificate.get_notAfter().decode('ascii'), X509_DATE_FMT)
            self.certificate_not_before = not_before.isoformat()
            self.certificate_not_after = not_after.isoformat()
            self.certificate_issued_desc = f'{(datetime.utcnow() - not_before).days} days ago'
            self.certificate_expiry_desc = f'Expired {(datetime.utcnow() - not_after).days} days ago' if not_after < datetime.utcnow() else f'Valid for {(not_after - datetime.utcnow()).days} days'
            self.asn_data = asn_data(self.host, self.port)

        return self

    def website_content(self):
        logger.info(f"website_content {self.host}")
        if self._content:
            return self._content

        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': f'http://{config.http_proxy}',
                'https': f'https://{config.https_proxy}'
            }
        try:
            logger.info(f"get _content {self.host}")
            self._content = requests.get(f'http://{self.host}',
                allow_redirects=True,
                proxies=proxies,
                timeout=3
            ).content
            logger.info(f"saved _content {self.host}")

        except Exception as ex:
            logger.exception(ex)

        logger.info(f"if _content {self.host}")
        if self._content:
            logger.info(f"size {self.host}")
            self.html_size = len(self._content)
            logger.info(f"title {self.host}")
            self.get_site_title()
            logger.info(f"scripts {self.host}")
            self.parse_scripts()
        logger.info(f"html done {self.host}")
        self.html_last_checked = datetime.utcnow().replace(microsecond=0).isoformat()

    @staticmethod
    def query_npm(package :str, version :str = None):
        url = f'https://www.npmjs.com/package/{package}'
        if version is not None:
            url += f'/v/{version}'
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': f'http://{config.http_proxy}',
                'https': f'https://{config.https_proxy}'
            }
        try:
            resp = requests.get(
                url,
                headers={
                    'User-Agent': config.user_agent,
                    'X-Requested-With': 'XMLHttpRequest',
                    'x-spiferack': '1',
                },
                proxies=proxies,
                timeout=3
            )
            if resp.status_code == 200:
                return resp.json()
        except IOError:
            pass
        except Exception as err:
            logger.exception(err)
        return None

    @staticmethod
    def parse_docstrings(docstrings :list):
        tests = [r'([\-\_\.a-zA-Z0-9]*)\.production\.min\.js', r'([\-\_\.a-zA-Z0-9]*)\.min\.js', r'.*\/([\-\_\.a-zA-Z0-9]*)\.js', r'https?:\/\/raw\.githubusercontent\.com\/([\-\_a-zA-Z0-9]*\/[\-\_a-zA-Z0-9]*)\/.*']
        scripts = []
        for docstring in docstrings:
            version = extract_semver(docstring)
            for test in tests:
                matches = re.findall(test, docstring, re.MULTILINE)
                package = matches[0]
                if package is not None:
                    break
            if package is None:
                continue
            if '/' in package: # from github link
                package = package.split('/')[1]
            npm_resp = Metadata.query_npm(package, version)
            if isinstance(npm_resp, dict) and 'capsule' in npm_resp:
                scripts.append({
                    'package': package,
                    'url': npm_resp.get('packageVersion', {}).get('homepage', npm_resp.get('packageVersion', {}).get('repository')),
                    'version': version,
                    'downloads': npm_resp.get('versionsDownloads', {}).get(version),
                    'latest_version': npm_resp.get('packument', {}).get('distTags', {}).get('latest'),
                    'dependencies': npm_resp.get('packageVersion', {}).get('dependencies', {}),
                    'dev_dependencies': npm_resp.get('packageVersion', {}).get('devDependencies', {}),
                    'last_updated': npm_resp.get('capsule', {}).get('lastPublish', {}).get('time'),
                    'license': npm_resp.get('packageVersion', {}).get('license'),
                    'docstring': docstring,
                })
        return scripts

    def parse_scripts(self):
        if self._content is None:
            return self.javascript
        soup = bs(self._content, 'html.parser')
        extracted = None
        docstrings = []
        code_blocks = [item.text for item in soup.find_all('script')]
        for code_block in code_blocks:
            docstrings += extract_docstrings(code_block)
        javascripts = [item['src'] for item in soup.select('script[src]')]
        proxies = None
        if config.http_proxy or config.https_proxy:
            proxies = {
                'http': f'http://{config.http_proxy}',
                'https': f'https://{config.https_proxy}'
            }
        for url in javascripts:
            try:
                script_content = requests.get(
                    url,
                    allow_redirects=True,
                    proxies=proxies,
                    timeout=3
                ).text
                if not script_content:
                    return None
                extracted = extract_docstrings(script_content)
                docstrings += extracted
            except Exception as ex:
                logger.exception(ex)
            query_string = None
            uri = '/'.join(url.split('/')[3:-1])
            filename_and_qs = url.split('/')[-1:]
            if '?' in filename_and_qs:
                filename, query_string = url.split('?')
            else:
                filename = filename_and_qs
            filename = filename.replace('.js', '').replace('.min', '')
            if query_string is not None:
                version = extract_semver(query_string)
            if version is None:
                version = extract_semver(filename)
            if version is None:
                version = extract_semver(uri)
            if version is None and extracted is not None:
                for comment in extracted:
                    if version.lower() in comment.lower():
                        version = extract_semver(comment)
            npm_resp = Metadata.query_npm(filename, version)
            if isinstance(npm_resp, dict) and 'capsule' in npm_resp:
                js_dict = {
                    'package': filename,
                    'url': url,
                    'version': version,
                    'downloads': npm_resp.get('versionsDownloads', {}).get(version),
                    'latest_version': npm_resp.get('packument', {}).get('distTags', {}).get('latest'),
                    'dependencies': npm_resp.get('packageVersion', {}).get('dependencies', {}),
                    'dev_dependencies': npm_resp.get('packageVersion', {}).get('devDependencies', {}),
                    'last_updated': npm_resp.get('capsule', {}).get('lastPublish', {}).get('time'),
                    'license': npm_resp.get('packageVersion', {}).get('license'),
                    'docstring': '\n'.join(extracted),
                }
                self.javascript.append(js_dict)

        self.javascript.extend(Metadata.parse_docstrings(docstrings))

        return self.javascript

    def get_site_title(self):
        if self._content is None:
            return self.html_title
        soup = bs(self._content, 'html.parser')
        title = soup.find('title')
        if title and isinstance(title.string, str):
            self.html_title = title.string.strip()

        return self.html_title

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
        except MaxRetryError:
            err = 'DNS Max Retry'
        except ConnectionResetError:
            err = 'Connection reset by peer'
        except NewConnectionError:
            err = 'Name or service not known'
        except ConnectionError:
            err = 'Name or service not known'
        except ConnectTimeout:
            err = 'DNS Timeout'
        except ConnectTimeoutError:
            err = 'DNS Timeout'
        except SocketError:
            err = 'Name or service not known'

        return res, err

    def verification_check(self, verification_hash):
        self.verification_hash, self.dns_answer = self.get_txt_value(self.host, 'trivialsec')
        self.txt_verification = self.verification_hash == verification_hash
        if self.verification_hash is False:
            self.txt_verification = False
            self.verification_hash = None
        return self

    @staticmethod
    def get_txt_value(domain_name :str, txt_key :str):
        dns_answer = None
        answers = []
        res, err = Metadata.dig(domain_name)
        if res is not None:
            for rrdata in res.response.answer:
                dns_answer = str(rrdata)
                for rtype in rrdata:
                    if isinstance(rtype, rdtypes.txtbase.TXTBase):
                        answers.append(str(rtype))

        if err == 'DNS Timeout':
            return False, dns_answer

        if len(answers) > 0:
            for record in answers:
                if f'{txt_key}=' not in record:
                    continue
                return record.replace('"', '').split('=')[1], dns_answer

        if err and 'None of DNS query names exist' in err:
            return False, dns_answer

        return None, dns_answer


def get_dns_value(domain_name :str, rdtype :int): # dns.rdatatype.RdataType
    dns_answer = None
    res, err = Metadata.dig(domain_name, rdtype=rdtype)
    if res is not None:
        for rrdata in res.response.answer:
            dns_answer = str(rrdata)

    if err:
        if 'None of DNS query names exist' in err:
            return False, dns_answer
        if err == 'DNS Timeout':
            return False, dns_answer

    return err, dns_answer

def get_nameservers(fqdn):
    try:
        ans = resolver.query(fqdn, 'NS')
        return [a.to_text() for a in ans]
    except DNSException:
        return []

def try_zone_transfer(domain):
    for nameserver in get_nameservers(domain):
        recs = None
        try:
            res = zone.from_xfr(query.xfr(nameserver, domain, lifetime=15))
            recs = [res[n].to_text(n) for n in res.nodes.keys()]
        except Exception:
            continue
        if recs is not None:
            return True, recs
    return False, None

@retry((SocketError), tries=3, delay=1.5, backoff=1)
def download_file(remote_file :str, temp_name :str = None, temp_dir :str = '/tmp') -> str:
    session = requests.Session()
    remote_file = remote_file.replace(":80/", "/").replace(":443/", "/")
    resp = session.head(remote_file, verify=remote_file.startswith('https'), allow_redirects=True, timeout=2)
    if not str(resp.status_code).startswith('2'):
        if resp.status_code == 403:
            logger.warning(f"Forbidden {remote_file}")
        elif resp.status_code == 404:
            logger.warning(f"Not Found {remote_file}")
            return None
        else:
            logger.error(f"Unexpected HTTP response code {resp.status_code} for URL {remote_file}")
            return None

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
            return temp_path

    etag = resp.headers.get('ETag')
    if etag:
        local_etag = None
        if path.exists(etag_path):
            with open(etag_path, 'r') as handle:
                local_etag = handle.read()
        if local_etag == etag:
            return temp_path

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

    return temp_path

@retry((SocketError), tries=5, delay=1.5, backoff=3, logger=logger)
def http_status(url :str):
    session = requests.Session()
    try:
        resp = session.head(url, verify=url.startswith('https'), allow_redirects=False, timeout=3)
        code = resp.status_code
        titles = _codes[code]
        status, *_ = titles
    except ReadTimeout:
        return 504, HTTP_504

    return code, status

def ip_for_host(host :str, ports :list = [80, 443]) -> list:
    ip_list = set()
    for port in ports:
        try:
            for family, _, _, _, sock_addr in getaddrinfo(host, port):
                if family == AF_INET6:
                    ip_list.add(sock_addr[0])
                if family == AF_INET:
                    ip_list.add(sock_addr[0])
        except IOError as ex:
            logger.exception(ex)
    return list(ip_list)

def asn_data(host :str, port :int = 80) -> list:
    as_data = []
    for addr in ip_for_host(host, [port]):
        if is_valid_ipv4_address(addr):
            try:
                as_data.append(get_as_data(addr)._asdict())
            except (NoASDataError, NonroutableAddressError, AddressFormatError) as ex:
                logger.exception(ex)
    return as_data

def request_from_raw(raw :str, encoding :str = 'unicode-escape') -> dict:
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

def cidr_address_list(cidr :str)->list:
    ret = []
    if '/' not in cidr:
        ret.append(cidr)
        return ret
    for ip_addr in ipaddress.IPv4Network(cidr, strict=False):
        if ip_addr.is_global:
            ret.append(str(ip_addr))

    return ret

def extract_semver(str_value :str):
    matches = re.search(SEMVER_REGEX, str_value)
    if matches:
        return matches.group()
    return None

def extract_docstrings(content :str):
    docstrings = []
    matches = re.finditer(DOCSTRING_REGEX, content, re.MULTILINE)
    for _, match in enumerate(matches, start=1):
        docstrings.append(match.group(1))
    return docstrings

def extract_server_version(str_value :str) -> tuple:
    trim_values = [
        'via:',
        'x-cache: miss',
        'x-cache: miss from',
    ]
    clean_names = [
        'cloudfront',
        'varnish',
        'wp engine',
        'microsoft-httpapi',
        'amazons3'
    ]
    ignore_list = [
        'no "server" line in header',
        'server-processing-duration-in-ticks:',
        'iterable-links',
        'x-cacheable: non',
        'x-cacheable: short',
        'nib.com.au',
    ]
    server_name = str_value.lower()
    for ignore_str in ignore_list:
        if ignore_str in server_name:
            return None, None

    for drop_str in trim_values:
        server_name = server_name.replace(drop_str, '').strip()

    server_version = None
    if '/' in server_name and len(server_name.split('/')) == 2:
        server_name, server_version = server_name.split('/')
        server_version = extract_semver(server_version)

    if server_version is None:
        server_version = extract_semver(server_name)

    if server_version is not None and server_version in server_name:
        server_name = server_name.replace(server_version, '')

    for name in clean_names:
        if name in str_value.lower():
            server_name = name

    if server_name == '':
        server_name = None
    if server_version is not None:
        server_version = server_version.strip()
    if server_name is not None:
        server_name = server_name.strip()

    return server_name, server_version

KNOWN_PORTS = {
    1: ('TCPMUX'),
    5: ('Remote Job Entry'),
    7: ('Echo'),
    9: ('Discard','Wake-on-LAN'),
    11: ('systat'),
    13: ('Daytime'),
    15: ('netstat'),
    17: ('QOTD'),
    18: ('MSP'),
    19: ('CHARGEN'),
    20: ('FTP'),
    21: ('FTP Control'),
    22: ('SSH'),
    23: ('Telnet'),
    25: ('SMTP'),
    28: ('Panorama HA'),
    37: ('Time'),
    42: ('NAMESERVER','WINS Replication'),
    43: ('WHOIS'),
    49: ('TACACS'),
    52: ('XNS Time Protocol'),
    53: ('DNS'),
    54: ('XNS Clearinghouse'),
    56: ('XNS Authentication Protocol'),
    58: ('XNS Mail'),
    67: ('DHCP','BOOTP'),
    68: ('DHCP','BOOTP'),
    69: ('TFTP'),
    70: ('Gopher'),
    71: ('NETRJS'),
    72: ('NETRJS'),
    73: ('NETRJS'),
    74: ('NETRJS'),
    79: ('Finger'),
    80: ('HTTP'),
    81: ('TorPark onion routing'),
    82: ('TorPark control'),
    83: ('MIT ML Device'),
    88: ('Kerberos'),
    90: ('PointCast'),
    95: ('SUPDUP'),
    101: ('NIC host name'),
    102: ('TSAP','MS Exchange'),
    104: ('DICOM'),
    105: ('CCSO name server'),
    107: ('RTelnet'),
    108: ('SNA'),
    109: ('POP2'),
    110: ('POP3'),
    111: ('ONC RPC'),
    118: ('SQL'),
    119: ('NNTP'),
    123: ('NTP'),
    126: ('NXEdit'),
    135: ('RPC','DCE Endpoint'),
    137: ('NetBIOS Name Service'),
    138: ('NetBIOS Datagram Service'),
    139: ('NetBIOS Session Service'),
    143: ('IMAP'),
    152: ('BFTP'),
    153: ('SGMP'),
    156: ('SQL'),
    158: ('DMSP','Pcmail'),
    161: ('SNMP'),
    162: ('SNMPTRAP'),
    170: ('Postscript print server'),
    177: ('XDMCP'),
    179: ('BGP'),
    194: ('IRC'),
    199: ('SMUX'),
    201: ('AppleTalk routing maintenance'),
    209: ('QMTP'),
    210: ('ANSI Z39.50'),
    213: ('IPX'),
    218: ('MPP'),
    220: ('IMAP version 3'),
    259: ('ESRO'),
    262: ('Arcisdms'),
    264: ('BGMP'),
    280: ('http-mgmt'),
    300: ('ThinLinc web access'),
    308: ('Novastor online backup'),
    311: ('Appleshare'),
    318: ('TSP'),
    319: ('PTP event messages'),
    320: ('PTP general messages'),
    350: ('MATIP type A'),
    351: ('MATIP type B'),
    356: ('Cloanto-net-1'),
    366: ('ODMR'),
    369: ('Rpc2portmap'),
    370: ('codaauth2','securecast1'),
    371: ('ClearCase albd'),
    376: ('Amiga Envoy Network Inquiry Protocol'),
    383: ('HP data alarm manager'),
    384: ('A remote network server system'),
    387: ('AURP'),
    388: ('Unidata LDM'),
    389: ('LDAP'),
    399: ('DECnet+'),
    401: ('UPS'),
    427: ('SLP'),
    433: ('NNTP'),
    434: ('Mobile IP Agent RFC 2944'),
    443: ('HTTPS'),
    444: ('SNPP RFC 1568'),
    445: ('Active Directory','SMB'),
    464: ('Kerberos change/set password'),
    465: (''),
    475: ('tcpnethaspsrv'),
    476: ('Centre Software ERP ports'),
    477: ('Centre Software ERP ports'),
    478: ('Centre Software ERP ports'),
    479: ('Centre Software ERP ports'),
    480: ('Centre Software ERP ports'),
    481: ('Centre Software ERP ports'),
    482: ('Centre Software ERP ports'),
    483: ('Centre Software ERP ports'),
    485: ('Centre Software ERP ports'),
    486: ('Centre Software ERP ports'),
    487: ('Centre Software ERP ports'),
    488: ('Centre Software ERP ports'),
    489: ('Centre Software ERP ports'),
    490: ('Centre Software ERP ports'),
    491: ('GO-Global remote access and application publishing software'),
    497: ('Retrospect'),
    500: ('ISAKMP','IKE'),
    502: ('Modbus protocol'),
    504: ('Citadel/UX'),
    510: ('FCP'),
    512: ('Rexec','comsat'),
    513: ('rlogin','who'),
    514: (''),
    515: ('LPD print service'),
    517: ('Talk'),
    518: ('NTalk'),
    520: ('efs','RIP'),
    521: ('RIPng'),
    524: ('NCP'),
    525: ('Timeserver'),
    530: ('RPC'),
    532: ('netnews'),
    533: ('netwall'),
    540: ('UUCP'),
    542: ('commerce'),
    543: ('klogin'),
    544: ('kshell'),
    546: ('DHCPv6'),
    547: ('DHCPv6'),
    548: ('AFP over TCP'),
    550: ('new-rwho','new-who'),
    554: ('RTSP'),
    556: ('Remotefs','RFS','rfs_server'),
    560: ('rmonitor','remote monitor'),
    561: ('monitor'),
    563: ('NNTPS'),
    587: ('SMTP'),
    591: ('Filemaker'),
    593: ('HTTP RPC EP Map'),
    601: ('Reliable syslog service'),
    604: ('TUNNEL profile'),
    623: ('ASF-RMCP','IPMI remote management protocol'),
    631: (''),
    635: ('RLZ DBase'),
    636: ('LDAPS'),
    639: ('MSDP'),
    641: ("SupportSoft Nexus Remote Command Control/Listening"),
    643: ('SANity'),
    646: ('LDP'),
    647: ('DHCP Failover protocol'),
    648: ('RRP'),
    651: ('IEEE-MMS'),
    653: ('SupportSoft Nexus Remote Command Data'),
    654: ('MMS','MMP'),
    655: ('Tinc VPN daemon'),
    657: ('IBM RMC'),
    660: ('MacOS Server administration'),
    666: (''),
    674: ('ACAP'),
    688: ('REALM-RUSD'),
    690: ('VATP'),
    691: ('MS Exchange Routing'),
    694: ('Linux-HA'),
    695: ('IEEE-MMS-SSL'),
    698: ('OLSR'),
    700: ('EPP'),
    701: ('LMP'),
    16300: ('Oracle WebCenter'),
    16384: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP','CISCO RTP MIN'),
    16385: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16386: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16387: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16393: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16394: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16395: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16396: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16397: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16398: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16399: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16400: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP','Oracle WebCenter Content'),
    16401: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16402: ('Apple Game Center RTCP','FaceTime RTCP','iChat RTCP'),
    16403: ('Apple Game Center RTCP','iChat RTCP'),
    16404: ('Apple Game Center RTCP'),
    16405: ('Apple Game Center RTCP'),
    16406: ('Apple Game Center RTCP'),
    16407: ('Apple Game Center RTCP'),
    16408: ('Apple Game Center RTCP'),
    16409: ('Apple Game Center RTCP'),
    16410: ('Apple Game Center RTCP'),
    16411: ('Apple Game Center RTCP'),
    16412: ('Apple Game Center RTCP'),
    16413: ('Apple Game Center RTCP'),
    16414: ('Apple Game Center RTCP'),
    16415: ('Apple Game Center RTCP'),
    16416: ('Apple Game Center RTCP'),
    16417: ('Apple Game Center RTCP'),
    16418: ('Apple Game Center RTCP'),
    16419: ('Apple Game Center RTCP'),
    16420: ('Apple Game Center RTCP'),
    16421: ('Apple Game Center RTCP'),
    16422: ('Apple Game Center RTCP'),
    16423: ('Apple Game Center RTCP'),
    16424: ('Apple Game Center RTCP'),
    16425: ('Apple Game Center RTCP'),
    16426: ('Apple Game Center RTCP'),
    16427: ('Apple Game Center RTCP'),
    16428: ('Apple Game Center RTCP'),
    16429: ('Apple Game Center RTCP'),
    16430: ('Apple Game Center RTCP'),
    16431: ('Apple Game Center RTCP'),
    16432: ('Apple Game Center RTCP'),
    16433: ('Apple Game Center RTCP'),
    16434: ('Apple Game Center RTCP'),
    16435: ('Apple Game Center RTCP'),
    16436: ('Apple Game Center RTCP'),
    16437: ('Apple Game Center RTCP'),
    16438: ('Apple Game Center RTCP'),
    16439: ('Apple Game Center RTCP'),
    16440: ('Apple Game Center RTCP'),
    16441: ('Apple Game Center RTCP'),
    16442: ('Apple Game Center RTCP'),
    16443: ('Apple Game Center RTCP'),
    16444: ('Apple Game Center RTCP'),
    16445: ('Apple Game Center RTCP'),
    16446: ('Apple Game Center RTCP'),
    16447: ('Apple Game Center RTCP'),
    16448: ('Apple Game Center RTCP'),
    16449: ('Apple Game Center RTCP'),
    16450: ('Apple Game Center RTCP'),
    16451: ('Apple Game Center RTCP'),
    16452: ('Apple Game Center RTCP'),
    16453: ('Apple Game Center RTCP'),
    16454: ('Apple Game Center RTCP'),
    16455: ('Apple Game Center RTCP'),
    16456: ('Apple Game Center RTCP'),
    16457: ('Apple Game Center RTCP'),
    16458: ('Apple Game Center RTCP'),
    16459: ('Apple Game Center RTCP'),
    16460: ('Apple Game Center RTCP'),
    16461: ('Apple Game Center RTCP'),
    16462: ('Apple Game Center RTCP'),
    16463: ('Apple Game Center RTCP'),
    16464: ('Apple Game Center RTCP'),
    16465: ('Apple Game Center RTCP'),
    16466: ('Apple Game Center RTCP'),
    16467: ('Apple Game Center RTCP'),
    16468: ('Apple Game Center RTCP'),
    16469: ('Apple Game Center RTCP'),
    16470: ('Apple Game Center RTCP'),
    16471: ('Apple Game Center RTCP'),
    16472: ('Apple Game Center RTCP'),
    16482: ('CISCO RTP MAX'),
    16567: ('Battlefield 2'),
    17011: ('Worms'),
    17224: ('TRDP'),
    17225: ('TRDP'),
    17333: ('CSMS'),
    17475: ('DMXControl 3 Network Broker'),
    17500: ('db-lsp'),
    18080: ('Monero P2P network'),
    18081: ('Monero incoming RPC'),
    18091: ('memcached'),
    18092: ('memcached'),
    18104: ('RAD PDF'),
    18200: ('Audition Online'),
    18201: ('Audition Online'),
    18206: ('Audition Online'),
    18300: ('Audition Online'),
    18301: ('Audition Online'),
    18306: ('Audition Online'),
    18333: ('Bitcoin testnet'),
    18400: ('Audition Online'),
    18401: ('Audition Online'),
    18505: ('Audition Online'),
    18506: ('Audition Online'),
    18605: ('X-BEAT'),
    18606: ('X-BEAT'),
    18676: ('YouView'),
    19000: ('JACK', 'Audition Online'),
    19001: ('Audition Online'),
    19132: ('Minecraft IPv4 multiplayer server'),
    19133: ('Minecraft IPv6 multiplayer server'),
    19150: ('Gkrellm Server'),
    19226: ('Panda Software AdminSecure'),
    19294: ('Google Talk'),
    19295: ('Google Talk'),
    19302: ('Google Talk'),
    19531: ('systemd-journal-gatewayd'),
    19532: ('systemd-journal-remote'),
    19812: ('4D database SQL'),
    19813: ('4D database'),
    19814: ('DB4D'),
    19999: ('DNP'),
    20000: ('DNP','Usermin','VoIP'),
    20560: ('Killing Floor'),
    20582: ('HW Development IoT comms'),
    20583: ('HW Development IoT comms'),
    20595: ('0AD'),
    20808: ('Ableton Link'),
    21025: ('Starbound'),
    22000: ('Syncthing'),
    22136: ('FLIR Systems'),
    22222: ('WeatherLink IP'),
    23073: ('Soldat'),
    23399: ('Skype'),
    23513: ('Duke Nukem 3D'),
    24441: ('Pyzor'),
    24444: ('NetBeans'),
    24465: ('Tonido Directory Server'),
    24554: ('BINKP','Fidonet'),
    24800: ('Synergy'),
    24842: ('StepMania: Online'),
    25565: ('Minecraft'),
    25575: ('Minecraft'),
    25826: ('collectd'),
    26000: ('Quake','EVE Online','Xonotic'),
    36900: ('EVE Online'),
    36901: ('EVE Online'),
    26909: ('Action Tanks Online'),
    26910: ('Action Tanks Online'),
    26911: ('Action Tanks Online'),
    27000: ('Steam','QuakeWorld','PowerBuilder SySAM license server'),
    27001: ('Steam','QuakeWorld'),
    27002: ('Steam','QuakeWorld'),
    27003: ('Steam','QuakeWorld'),
    27004: ('Steam','QuakeWorld'),
    27005: ('Steam','QuakeWorld'),
    27006: ('Steam','QuakeWorld'),
    27007: ('Steam'),
    27008: ('Steam'),
    27009: ('Steam'),
    27010: ('Steam'),
    27011: ('Steam'),
    27012: ('Steam'),
    27013: ('Steam'),
    27014: ('Steam'),
    27015: ('Steam matchmaking','HLTV','Unturned','GoldSrc','Source engine'),
    27016: ('Magicka','Space Engineers','Steam matchmaking','HLTV','Unturned'),
    27017: ('MongoDB','Steam matchmaking','HLTV','Unturned'),
    27018: ('Steam matchmaking','HLTV','Unturned'),
    27019: ('Steam matchmaking','HLTV'),
    27020: ('Steam matchmaking','HLTV'),
    27021: ('Steam matchmaking','HLTV'),
    27022: ('Steam matchmaking','HLTV'),
    27023: ('Steam matchmaking','HLTV'),
    27024: ('Steam matchmaking','HLTV'),
    27025: ('Steam matchmaking','HLTV'),
    27026: ('Steam matchmaking','HLTV'),
    27027: ('Steam matchmaking','HLTV'),
    27028: ('Steam matchmaking','HLTV'),
    27029: ('Steam matchmaking','HLTV'),
    27030: ('Steam matchmaking','HLTV'),
    27031: ('Steam'),
    27036: ('Steam'),
    27037: ('Steam'),
    27374: ('Sub7'),
    27500: ('QuakeWorld'),
    27501: ('QuakeWorld'),
    27502: ('QuakeWorld'),
    27503: ('QuakeWorld'),
    27504: ('QuakeWorld'),
    27505: ('QuakeWorld'),
    27506: ('QuakeWorld'),
    27507: ('QuakeWorld'),
    27508: ('QuakeWorld'),
    27509: ('QuakeWorld'),
    27510: ('QuakeWorld'),
    27511: ('QuakeWorld'),
    27512: ('QuakeWorld'),
    27513: ('QuakeWorld'),
    27514: ('QuakeWorld'),
    27515: ('QuakeWorld'),
    27516: ('QuakeWorld'),
    27517: ('QuakeWorld'),
    27518: ('QuakeWorld'),
    27519: ('QuakeWorld'),
    27520: ('QuakeWorld'),
    27521: ('QuakeWorld'),
    27522: ('QuakeWorld'),
    27523: ('QuakeWorld'),
    27524: ('QuakeWorld'),
    27525: ('QuakeWorld'),
    27526: ('QuakeWorld'),
    27527: ('QuakeWorld'),
    27528: ('QuakeWorld'),
    27529: ('QuakeWorld'),
    27530: ('QuakeWorld'),
    27531: ('QuakeWorld'),
    27532: ('QuakeWorld'),
    27533: ('QuakeWorld'),
    27534: ('QuakeWorld'),
    27535: ('QuakeWorld'),
    27536: ('QuakeWorld'),
    27537: ('QuakeWorld'),
    27538: ('QuakeWorld'),
    27539: ('QuakeWorld'),
    27540: ('QuakeWorld'),
    27541: ('QuakeWorld'),
    27542: ('QuakeWorld'),
    27543: ('QuakeWorld'),
    27544: ('QuakeWorld'),
    27545: ('QuakeWorld'),
    27546: ('QuakeWorld'),
    27547: ('QuakeWorld'),
    27548: ('QuakeWorld'),
    27549: ('QuakeWorld'),
    27550: ('QuakeWorld'),
    27551: ('QuakeWorld'),
    27552: ('QuakeWorld'),
    27553: ('QuakeWorld'),
    27554: ('QuakeWorld'),
    27555: ('QuakeWorld'),
    27556: ('QuakeWorld'),
    27557: ('QuakeWorld'),
    27558: ('QuakeWorld'),
    27559: ('QuakeWorld'),
    27560: ('QuakeWorld'),
    27561: ('QuakeWorld'),
    27562: ('QuakeWorld'),
    27563: ('QuakeWorld'),
    27564: ('QuakeWorld'),
    27565: ('QuakeWorld'),
    27566: ('QuakeWorld'),
    27567: ('QuakeWorld'),
    27568: ('QuakeWorld'),
    27569: ('QuakeWorld'),
    27570: ('QuakeWorld'),
    27571: ('QuakeWorld'),
    27572: ('QuakeWorld'),
    27573: ('QuakeWorld'),
    27574: ('QuakeWorld'),
    27575: ('QuakeWorld'),
    27576: ('QuakeWorld'),
    27577: ('QuakeWorld'),
    27578: ('QuakeWorld'),
    27579: ('QuakeWorld'),
    27580: ('QuakeWorld'),
    27581: ('QuakeWorld'),
    27582: ('QuakeWorld'),
    27583: ('QuakeWorld'),
    27584: ('QuakeWorld'),
    27585: ('QuakeWorld'),
    27586: ('QuakeWorld'),
    27587: ('QuakeWorld'),
    27588: ('QuakeWorld'),
    27589: ('QuakeWorld'),
    27590: ('QuakeWorld'),
    27591: ('QuakeWorld'),
    27592: ('QuakeWorld'),
    27593: ('QuakeWorld'),
    27594: ('QuakeWorld'),
    27595: ('QuakeWorld'),
    27596: ('QuakeWorld'),
    27597: ('QuakeWorld'),
    27598: ('QuakeWorld'),
    27599: ('QuakeWorld'),
    27600: ('QuakeWorld'),
    27601: ('QuakeWorld'),
    27602: ('QuakeWorld'),
    27603: ('QuakeWorld'),
    27604: ('QuakeWorld'),
    27605: ('QuakeWorld'),
    27606: ('QuakeWorld'),
    27607: ('QuakeWorld'),
    27608: ('QuakeWorld'),
    27609: ('QuakeWorld'),
    27610: ('QuakeWorld'),
    27611: ('QuakeWorld'),
    27612: ('QuakeWorld'),
    27613: ('QuakeWorld'),
    27614: ('QuakeWorld'),
    27615: ('QuakeWorld'),
    27616: ('QuakeWorld'),
    27617: ('QuakeWorld'),
    27618: ('QuakeWorld'),
    27619: ('QuakeWorld'),
    27620: ('QuakeWorld'),
    27621: ('QuakeWorld'),
    27622: ('QuakeWorld'),
    27623: ('QuakeWorld'),
    27624: ('QuakeWorld'),
    27625: ('QuakeWorld'),
    27626: ('QuakeWorld'),
    27627: ('QuakeWorld'),
    27628: ('QuakeWorld'),
    27629: ('QuakeWorld'),
    27630: ('QuakeWorld'),
    27631: ('QuakeWorld'),
    27632: ('QuakeWorld'),
    27633: ('QuakeWorld'),
    27634: ('QuakeWorld'),
    27635: ('QuakeWorld'),
    27636: ('QuakeWorld'),
    27637: ('QuakeWorld'),
    27638: ('QuakeWorld'),
    27639: ('QuakeWorld'),
    27640: ('QuakeWorld'),
    27641: ('QuakeWorld'),
    27642: ('QuakeWorld'),
    27643: ('QuakeWorld'),
    27644: ('QuakeWorld'),
    27645: ('QuakeWorld'),
    27646: ('QuakeWorld'),
    27647: ('QuakeWorld'),
    27648: ('QuakeWorld'),
    27649: ('QuakeWorld'),
    27650: ('QuakeWorld'),
    27651: ('QuakeWorld'),
    27652: ('QuakeWorld'),
    27653: ('QuakeWorld'),
    27654: ('QuakeWorld'),
    27655: ('QuakeWorld'),
    27656: ('QuakeWorld'),
    27657: ('QuakeWorld'),
    27658: ('QuakeWorld'),
    27659: ('QuakeWorld'),
    27660: ('QuakeWorld'),
    27661: ('QuakeWorld'),
    27662: ('QuakeWorld'),
    27663: ('QuakeWorld'),
    27664: ('QuakeWorld'),
    27665: ('QuakeWorld'),
    27666: ('QuakeWorld'),
    27667: ('QuakeWorld'),
    27668: ('QuakeWorld'),
    27669: ('QuakeWorld'),
    27670: ('QuakeWorld'),
    27671: ('QuakeWorld'),
    27672: ('QuakeWorld'),
    27673: ('QuakeWorld'),
    27674: ('QuakeWorld'),
    27675: ('QuakeWorld'),
    27676: ('QuakeWorld'),
    27677: ('QuakeWorld'),
    27678: ('QuakeWorld'),
    27679: ('QuakeWorld'),
    27680: ('QuakeWorld'),
    27681: ('QuakeWorld'),
    27682: ('QuakeWorld'),
    27683: ('QuakeWorld'),
    27684: ('QuakeWorld'),
    27685: ('QuakeWorld'),
    27686: ('QuakeWorld'),
    27687: ('QuakeWorld'),
    27688: ('QuakeWorld'),
    27689: ('QuakeWorld'),
    27690: ('QuakeWorld'),
    27691: ('QuakeWorld'),
    27692: ('QuakeWorld'),
    27693: ('QuakeWorld'),
    27694: ('QuakeWorld'),
    27695: ('QuakeWorld'),
    27696: ('QuakeWorld'),
    27697: ('QuakeWorld'),
    27698: ('QuakeWorld'),
    27699: ('QuakeWorld'),
    27700: ('QuakeWorld'),
    27701: ('QuakeWorld'),
    27702: ('QuakeWorld'),
    27703: ('QuakeWorld'),
    27704: ('QuakeWorld'),
    27705: ('QuakeWorld'),
    27706: ('QuakeWorld'),
    27707: ('QuakeWorld'),
    27708: ('QuakeWorld'),
    27709: ('QuakeWorld'),
    27710: ('QuakeWorld'),
    27711: ('QuakeWorld'),
    27712: ('QuakeWorld'),
    27713: ('QuakeWorld'),
    27714: ('QuakeWorld'),
    27715: ('QuakeWorld'),
    27716: ('QuakeWorld'),
    27717: ('QuakeWorld'),
    27718: ('QuakeWorld'),
    27719: ('QuakeWorld'),
    27720: ('QuakeWorld'),
    27721: ('QuakeWorld'),
    27722: ('QuakeWorld'),
    27723: ('QuakeWorld'),
    27724: ('QuakeWorld'),
    27725: ('QuakeWorld'),
    27726: ('QuakeWorld'),
    27727: ('QuakeWorld'),
    27728: ('QuakeWorld'),
    27729: ('QuakeWorld'),
    27730: ('QuakeWorld'),
    27731: ('QuakeWorld'),
    27732: ('QuakeWorld'),
    27733: ('QuakeWorld'),
    27734: ('QuakeWorld'),
    27735: ('QuakeWorld'),
    27736: ('QuakeWorld'),
    27737: ('QuakeWorld'),
    27738: ('QuakeWorld'),
    27739: ('QuakeWorld'),
    27740: ('QuakeWorld'),
    27741: ('QuakeWorld'),
    27742: ('QuakeWorld'),
    27743: ('QuakeWorld'),
    27744: ('QuakeWorld'),
    27745: ('QuakeWorld'),
    27746: ('QuakeWorld'),
    27747: ('QuakeWorld'),
    27748: ('QuakeWorld'),
    27749: ('QuakeWorld'),
    27750: ('QuakeWorld'),
    27751: ('QuakeWorld'),
    27752: ('QuakeWorld'),
    27753: ('QuakeWorld'),
    27754: ('QuakeWorld'),
    27755: ('QuakeWorld'),
    27756: ('QuakeWorld'),
    27757: ('QuakeWorld'),
    27758: ('QuakeWorld'),
    27759: ('QuakeWorld'),
    27760: ('QuakeWorld'),
    27761: ('QuakeWorld'),
    27762: ('QuakeWorld'),
    27763: ('QuakeWorld'),
    27764: ('QuakeWorld'),
    27765: ('QuakeWorld'),
    27766: ('QuakeWorld'),
    27767: ('QuakeWorld'),
    27768: ('QuakeWorld'),
    27769: ('QuakeWorld'),
    27770: ('QuakeWorld'),
    27771: ('QuakeWorld'),
    27772: ('QuakeWorld'),
    27773: ('QuakeWorld'),
    27774: ('QuakeWorld'),
    27775: ('QuakeWorld'),
    27776: ('QuakeWorld'),
    27777: ('QuakeWorld'),
    27778: ('QuakeWorld'),
    27779: ('QuakeWorld'),
    27780: ('QuakeWorld'),
    27781: ('QuakeWorld'),
    27782: ('QuakeWorld'),
    27783: ('QuakeWorld'),
    27784: ('QuakeWorld'),
    27785: ('QuakeWorld'),
    27786: ('QuakeWorld'),
    27787: ('QuakeWorld'),
    27788: ('QuakeWorld'),
    27789: ('QuakeWorld'),
    27790: ('QuakeWorld'),
    27791: ('QuakeWorld'),
    27792: ('QuakeWorld'),
    27793: ('QuakeWorld'),
    27794: ('QuakeWorld'),
    27795: ('QuakeWorld'),
    27796: ('QuakeWorld'),
    27797: ('QuakeWorld'),
    27798: ('QuakeWorld'),
    27799: ('QuakeWorld'),
    27800: ('QuakeWorld'),
    27801: ('QuakeWorld'),
    27802: ('QuakeWorld'),
    27803: ('QuakeWorld'),
    27804: ('QuakeWorld'),
    27805: ('QuakeWorld'),
    27806: ('QuakeWorld'),
    27807: ('QuakeWorld'),
    27808: ('QuakeWorld'),
    27809: ('QuakeWorld'),
    27810: ('QuakeWorld'),
    27811: ('QuakeWorld'),
    27812: ('QuakeWorld'),
    27813: ('QuakeWorld'),
    27814: ('QuakeWorld'),
    27815: ('QuakeWorld'),
    27816: ('QuakeWorld'),
    27817: ('QuakeWorld'),
    27818: ('QuakeWorld'),
    27819: ('QuakeWorld'),
    27820: ('QuakeWorld'),
    27821: ('QuakeWorld'),
    27822: ('QuakeWorld'),
    27823: ('QuakeWorld'),
    27824: ('QuakeWorld'),
    27825: ('QuakeWorld'),
    27826: ('QuakeWorld'),
    27827: ('QuakeWorld'),
    27828: ('QuakeWorld'),
    27829: ('QuakeWorld'),
    27830: ('QuakeWorld'),
    27831: ('QuakeWorld'),
    27832: ('QuakeWorld'),
    27833: ('QuakeWorld'),
    27834: ('QuakeWorld'),
    27835: ('QuakeWorld'),
    27836: ('QuakeWorld'),
    27837: ('QuakeWorld'),
    27838: ('QuakeWorld'),
    27839: ('QuakeWorld'),
    27840: ('QuakeWorld'),
    27841: ('QuakeWorld'),
    27842: ('QuakeWorld'),
    27843: ('QuakeWorld'),
    27844: ('QuakeWorld'),
    27845: ('QuakeWorld'),
    27846: ('QuakeWorld'),
    27847: ('QuakeWorld'),
    27848: ('QuakeWorld'),
    27849: ('QuakeWorld'),
    27850: ('QuakeWorld'),
    27851: ('QuakeWorld'),
    27852: ('QuakeWorld'),
    27853: ('QuakeWorld'),
    27854: ('QuakeWorld'),
    27855: ('QuakeWorld'),
    27856: ('QuakeWorld'),
    27857: ('QuakeWorld'),
    27858: ('QuakeWorld'),
    27859: ('QuakeWorld'),
    27860: ('QuakeWorld'),
    27861: ('QuakeWorld'),
    27862: ('QuakeWorld'),
    27863: ('QuakeWorld'),
    27864: ('QuakeWorld'),
    27865: ('QuakeWorld'),
    27866: ('QuakeWorld'),
    27867: ('QuakeWorld'),
    27868: ('QuakeWorld'),
    27869: ('QuakeWorld'),
    27870: ('QuakeWorld'),
    27871: ('QuakeWorld'),
    27872: ('QuakeWorld'),
    27873: ('QuakeWorld'),
    27874: ('QuakeWorld'),
    27875: ('QuakeWorld'),
    27876: ('QuakeWorld'),
    27877: ('QuakeWorld'),
    27878: ('QuakeWorld'),
    27879: ('QuakeWorld'),
    27880: ('QuakeWorld'),
    27881: ('QuakeWorld'),
    27882: ('QuakeWorld'),
    27883: ('QuakeWorld'),
    27884: ('QuakeWorld'),
    27885: ('QuakeWorld'),
    27886: ('QuakeWorld'),
    27887: ('QuakeWorld'),
    27888: ('QuakeWorld','Kaillera'),
    27889: ('QuakeWorld'),
    27890: ('QuakeWorld'),
    27891: ('QuakeWorld'),
    27892: ('QuakeWorld'),
    27893: ('QuakeWorld'),
    27894: ('QuakeWorld'),
    27895: ('QuakeWorld'),
    27896: ('QuakeWorld'),
    27897: ('QuakeWorld'),
    27898: ('QuakeWorld'),
    27899: ('QuakeWorld'),
    27900: ('QuakeWorld'),
    27901: ('Quake'),
    27902: ('Quake'),
    27903: ('Quake'),
    27904: ('Quake'),
    27905: ('Quake'),
    27906: ('Quake'),
    27907: ('Quake'),
    27908: ('Quake'),
    27909: ('Quake'),
    27910: ('Quake'),
    27950: ('OpenArena'),
    37960: ('Quake','Enemy Territory', 'OpenArena'),
    37961: ('Quake','Enemy Territory', 'OpenArena'),
    37962: ('Quake','Enemy Territory', 'OpenArena'),
    37963: ('Quake','Enemy Territory', 'OpenArena'),
    37964: ('Quake','Enemy Territory', 'OpenArena'),
    37965: ('Quake','Enemy Territory', 'OpenArena'),
    37966: ('Quake','Enemy Territory', 'OpenArena'),
    37967: ('Quake','Enemy Territory', 'OpenArena'),
    37968: ('Quake','Enemy Territory', 'OpenArena'),
    37969: ('Quake','Enemy Territory', 'OpenArena'),
    28000: ('Siemens PLM Software license server'),
    28001: ('Starsiege: Tribes'),
    28015: ('Rust'),
    28016: ('Rust RCON'),
    28260: ('Palo Alto Networks Panorama unencrypted'),
    28443: ('Palo Alto Networks Panorama updates'),
    28769: ('Palo Alto Panorama unencrypted'),
    28770: ('Palo Alto Panorama encrypted','AssaultCube'),
    28771: ('AssaultCube'),
    28785: ('Cube 2: Sauerbraten'),
    28786: ('Cube 2: Sauerbraten'),
    28852: ('Killing Floor'),
    28910: ('Nintendo Wi-Fi'),
    28960: ('Call of Duty'),
    29000: ('Perfect World'),
    29070: ('Jedi Knight: Jedi Academy'),
    29900: ('Nintendo Wi-Fi'),
    29901: ('Nintendo Wi-Fi'),
    29920: ('Nintendo Wi-Fi'),
    30000: ('XLink Kai P2P','Minetest'),
    30033: ('TeamSpeak 3 File Transfer'),
    30564: ('Multiplicity'),
    31337: ('Back Orifice'),
    31416: ('BOINC RPC'),
    31438: ('Rocket U2'),
    31457: ('TetriNET'),
    32137: ('Immunet Protect'),
    32400: ('Plex'),
    32764: ('backdoor'),
    32887: ('Ace of Spades'),
    32976: ('VPN'),
    33434: ('traceroute'),
    33848: ('Jenkins'),
    34000: ('Infestation: Survivor Stories'),
    34197: ('Factorio'),
    35357: ('OpenStack Identity'),
    36330: ('Folding@home Control Port'),
    37008: ('TZSP'),
    40000: ('SafetyNET p'),
    41121: ('Tentacle Server'),
    41794: ('Crestron Control Port'),
    41795: ('Crestron Secure Terminal Port'),
    41796: ('Crestron Secure Control Port'),
    41797: ('Crestron Secure Terminal Port'),
    43110: ('ZeroNet'),
    43594: ('RuneScape'),
    43595: ('RuneScape'),
    47805: ('MU Online'),
    47808: ('BACnet'),
    47809: ('BACnet'),
    47810: ('BACnet'),
    47811: ('BACnet'),
    47812: ('BACnet'),
    47813: ('BACnet'),
    47814: ('BACnet'),
    47815: ('BACnet'),
    47816: ('BACnet'),
    47817: ('BACnet'),
    47818: ('BACnet','CIP'),
    47819: ('BACnet'),
    47820: ('BACnet'),
    47821: ('BACnet'),
    47822: ('BACnet'),
    47823: ('BACnet'),
}
def find_open_ports(hostname :str):
    for port, _ in KNOWN_PORTS.items():
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.settimeout(1)
            res = sock.connect_ex((hostname, port))
            sock.settimeout(None)
            if res == 0:
                yield port
