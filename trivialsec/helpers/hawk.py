from urllib.parse import urlparse
from base64 import b64encode
from datetime import datetime, timedelta
import re
import hmac
import hashlib
import redis
from gunicorn.glogging import logging


__module__       = 'trivialsec.helpers.hawk'
__version__      = "0.1.0"
__description__  = "Hawk Access Authentication protocol"
__license__      = "Proprietary"
__author__       = 'Trivial Security'
__author_email__ = 'support@trivialsec.com'
__keywords__     = 'authentication Hawk HTTP request signing'

logger = logging.getLogger(__name__)
supported_digests = {
    'HMAC-SHA256': hashlib.sha256,
    'HMAC-SHA512': hashlib.sha512,
    'HMAC-SHA3-256': hashlib.sha3_256,
    'HMAC-SHA3-384': hashlib.sha3_384,
    'HMAC-SHA3-512': hashlib.sha3_512,
    'HMAC-BLAKE2B512': hashlib.blake2b,
}


class Hawk:
    version :int = 1
    algorithm :str
    server_hash :str
    server_mac :str
    _params :dict = dict()
    _authorization_header :str
    _request_method :str
    _request_host :str
    _path_uri :str
    _raw :str
    _content_type :str
    _optional_payload_validation :bool = False
    _not_before_seconds :int = 3
    _expire_after_seconds :int = 3
    _nonce_store :str = 'file' # redis, file
    _redis_config :dict
    _redis :redis.Redis
    _append_only_file :str

    @property
    def scheme(self):
        return self._params.get('scheme')

    @property
    def id(self):
        return self._params.get('id')

    @property
    def ts(self):
        return int(self._params.get('ts'))

    @property
    def nonce(self):
        return self._params.get('nonce')

    @property
    def hash(self):
        return self._params.get('hash')

    @property
    def mac(self):
        return self._params.get('mac')

    @property
    def app(self):
        return self._params.get('app')

    @property
    def dlg(self):
        return self._params.get('dlg')

    @property
    def ext(self):
        return self._params.get('ext')

    def __init__(self, authorization_header :str, request_method :str, path_uri :str, host :str, utf8_body :str = None, content_type :str = None, algorithm :str = "HMAC-SHA256", options :dict = None) -> None:
        self._authorization_header = authorization_header.strip()
        self.algorithm = algorithm
        self._request_method = request_method
        self._request_host = host
        self._path_uri = path_uri
        self._raw = utf8_body
        self._content_type = content_type.split(';')[0].strip().lower()
        self._parse_auth_header()
        if options is not None:
            self._apply_options(options)
        if self._nonce_store == 'redis' and self._redis_config:
            self._init_redis()
        if self._optional_payload_validation is True and (content_type is None or utf8_body is None):
            raise ValueError('HawkError utf8_body and content_type are both required for payload_validation')

    def _init_redis(self):
        if not isinstance(self._redis_config, dict):
            raise ValueError('HawkError redis_config dict is required for nonce_store using redis')
        self._redis = redis.Redis(**self._redis_config)

    def _parse_auth_header(self) -> None:
        auth_param_re = r'([a-zA-Z0-9_\-]+)=(([a-zA-Z0-9_\-]+)|("")|(".*[^\\]"))'
        auth_param_re = re.compile(r"^\s*" + auth_param_re + r"\s*$")
        unesc_quote_re = re.compile(r'(^")|([^\\]")')
        authz = self._authorization_header
        scheme, pairs_str = authz.split(None, 1)
        self._params = {"scheme": scheme}
        pairs = []
        if pairs_str:
            for pair in pairs_str.split(","):
                if not pairs or auth_param_re.match(pairs[-1]):
                    pairs.append(pair)
                else:
                    pairs[-1] = pairs[-1] + "," + pair
            if not auth_param_re.match(pairs[-1]):
                raise ValueError('Malformed auth parameters')
        for pair in pairs:
            (key, value) = pair.strip().split("=", 1)
            # For quoted strings, remove quotes and backslash-escapes.
            if value.startswith('"'):
                value = value[1:-1]
                if unesc_quote_re.search(value):
                    raise ValueError("Unescaped quote in quoted-string")
                value = re.compile(r"\\.").sub(lambda m: m.group(0)[1], value)
            self._params[key] = value

    def _apply_options(self, options :dict = None) -> None:
        if options is None:
            return
        self._not_before_seconds = options.get('not_before', self._not_before_seconds)
        self._expire_after_seconds = options.get('expire_after', self._expire_after_seconds)
        self._optional_payload_validation = options.get('payload_validation', self._optional_payload_validation)
        self._nonce_store = options.get('nonce_store', self._nonce_store)
        if self._nonce_store not in ['redis', 'file']:
            raise NotImplementedError(f'HawkError nonce_store {self._nonce_store} must be either "redis" or "file"')
        if self._nonce_store == 'redis':
            self._redis_config = options.get('redis_config')
        if self._nonce_store == 'append_only_file':
            self._append_only_file = options.get('file_path', '/tmp/hawk_nonce_store.log')

    def _signing_data(self) -> str:
        parsed_url = urlparse(f'http://{self._request_host}')
        port = 443 if parsed_url.port is None else parsed_url.port

        bits = []
        bits.append("hawk.1.header")
        bits.append(str(self.ts))
        bits.append(self.nonce)
        bits.append(self._request_method.upper())
        bits.append(self._path_uri)
        bits.append(parsed_url.hostname.lower())
        bits.append(str(port))
        bits.append(self.server_hash)
        bits.append(self.ext or '')
        if self.app is not None:
            bits.append(self.app)
            bits.append(self.dlg or '')

        bits.append('') # trailing newline
        return "\n".join(bits).encode("utf8")

    def is_valid_scheme(self) -> bool:
        return self._authorization_header.startswith('Hawk')

    def is_valid_nonce(self) -> bool:
        return True

    def is_valid_payload(self) -> bool:
        payload_hash = supported_digests.get(self.algorithm)()
        payload_hash.update(b"hawk.1.payload\n")
        payload_hash.update(self._content_type.encode("utf8"))
        payload_hash.update(b"\n")
        payload_hash.update(self._raw)
        payload_hash.update(b"\n") # trailing newline
        server_hash = b64encode(payload_hash.digest())
        self.server_hash = server_hash
        return self._compare(server_hash.decode('utf8'), self.hash)

    def is_valid_timestamp(self) -> bool:
        # not_before prevents replay attacks
        compare_date = datetime.fromtimestamp(self.ts)
        not_before = datetime.utcnow() - timedelta(seconds=self._not_before_seconds)
        expire_after = datetime.utcnow() + timedelta(seconds=self._expire_after_seconds)
        # expire_after can assist with support for offline/aeroplane mode
        if compare_date < not_before or compare_date > expire_after:
            logger.info(f'compare_date {compare_date} not_before {not_before} expire_after {expire_after}')
            return False
        return True

    def validate(self, secret :str) -> bool:
        if not self.is_valid_scheme():
            logger.error('incompatible authorization scheme, expected "Authorization: Hawk ..."')
            return False
        if not self.is_valid_nonce():
            logger.error(f'bad nonce {self.nonce}')
            return False
        if not self.is_valid_timestamp():
            logger.error(f'jitter detected {self.ts}')
            return False
        if self._optional_payload_validation is True and not self.is_valid_payload():
            logger.error(f'payload validation failed content_type {self._content_type} raw {self._raw} server_hash {self.server_hash} hash {self.hash}')
            return False
        if self.algorithm not in supported_digests.keys():
            logger.error(f'algorithm {self.algorithm} is not supported')
            return False

        digestmod = supported_digests.get(self.algorithm)
        # Sign HMAC using server-side secret
        digest = hmac.new(secret.encode('ascii'), self._signing_data(), digestmod).digest()
        self.server_mac = b64encode(digest)
        # Compare server-side HMAC with client provided HMAC
        return self._compare(self.server_mac.decode('utf8'), self.mac)

    @staticmethod
    def _compare(*values):
        """
        _compare() takes two or more str or byte-like inputs and compares
        each to return True if they match or False if there is any mismatch
        """
        # In Python 3, if we have a bytes object, iterating it will already get the integer value
        def chk_bytes(val):
            return val if isinstance(val, (bytes, bytearray)) else val.encode('utf8')
        result = 0
        for index, this in enumerate(values):
            if index == 0: # first index has nothing to compare
                continue
            prev = values[index-1]              # use the index variable i to locate prev
            # Constant time string comparision, mitigates side channel attacks.
            if len(prev) != len(this):
                return False
            for _x, _y in zip(prev, this):
                result |= chk_bytes(_x) ^ chk_bytes(_y)
        return result == 0
