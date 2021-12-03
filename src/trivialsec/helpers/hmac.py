from base64 import b64encode
from datetime import datetime, timedelta
from urllib.parse import urlparse
import re
import hmac
import hashlib
from gunicorn.glogging import logging
from trivialsec.helpers.config import config


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers.hmac'

class HMAC:
    auth_param_re = r'([a-zA-Z0-9_\-]+)=(([a-zA-Z0-9_\-]+)|("")|(".*[^\\]"))'
    auth_param_re = re.compile(r"^\s*" + auth_param_re + r"\s*$")
    unesc_quote_re = re.compile(r'(^")|([^\\]")')
    default_algorithm = 'sha512'
    supported_algorithms = {
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'sha3_256': hashlib.sha3_256,
        'sha3_384': hashlib.sha3_384,
        'sha3_512': hashlib.sha3_512,
        'blake2b512': hashlib.blake2b,
    }
    server_mac :str
    parsed_header :dict = dict()
    _not_before_seconds :int = 3
    _expire_after_seconds :int = 3

    @property
    def scheme(self):
        return self.parsed_header.get('scheme')

    @property
    def id(self):
        return self.parsed_header.get('id')

    @property
    def ts(self):
        return int(self.parsed_header.get('ts'))

    @property
    def nonce(self):
        return self.parsed_header.get('nonce')

    @property
    def mac(self):
        return self.parsed_header.get('mac')

    @property
    def canonical_string(self) -> str:
        parsed_url = urlparse(self.request.base_url)
        port = 443 if parsed_url.port is None else parsed_url.port
        bits = []
        bits.append(str(self.ts))
        bits.append(self.nonce)
        bits.append(self.request.method.upper())
        bits.append(self.request.path)
        bits.append(parsed_url.hostname.lower())
        bits.append(str(port))
        bits.append(b64encode(self.raw.encode('utf8')).decode('utf8'))
        return "\n".join(bits)

    def __init__(self, request, algorithm :str = 'sha512', expire_after_seconds :int = 3, not_before_seconds :int = 3):
        self.authorization_header = request.headers.get('Authorization')
        self.raw = request.get_data(as_text=True)
        self.request = request
        if algorithm not in self.supported_algorithms.keys():
            algorithm = self.default_algorithm
        self.algorithm = algorithm
        self._expire_after_seconds = expire_after_seconds
        self._not_before_seconds = not_before_seconds
        self._parse_auth_header()

    def _parse_auth_header(self) -> None:
        scheme, pairs_str = self.authorization_header.split(None, 1)
        self.parsed_header = {"scheme": scheme}
        pairs = []
        if pairs_str:
            for pair in pairs_str.split(","):
                if not pairs or self.auth_param_re.match(pairs[-1]):
                    pairs.append(pair)
                else:
                    pairs[-1] = pairs[-1] + "," + pair
            if not self.auth_param_re.match(pairs[-1]):
                raise ValueError('Malformed auth parameters')
        for pair in pairs:
            (key, value) = pair.strip().split("=", 1)
            # For quoted strings, remove quotes and backslash-escapes.
            if value.startswith('"'):
                value = value[1:-1]
                if self.unesc_quote_re.search(value):
                    raise ValueError("Unescaped quote in quoted-string")
                value = re.compile(r"\\.").sub(lambda m: m.group(0)[1], value)
            self.parsed_header[key] = value

    def is_valid_nonce(self) -> bool:
        key = f'{self.id}:{self.nonce}:{self.ts}'
        if config.redis_client.get(key):
            # We have already processed this nonce + timestamp.
            return False
        # Save this nonce + timestamp for later.
        config.redis_client.set(key, '1')
        return True

    def is_valid_scheme(self) -> bool:
        return self.authorization_header.startswith('HMAC')

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

    @staticmethod
    def _compare(*values):
        """
        _compare() takes two or more str or byte-like inputs and compares
        each to return True if they match or False if there is any mismatch
        """
        # In Python 3, if we have a bytes object, iterating it will already get the integer value
        def chk_bytes(val):
            return ord(val if isinstance(val, (bytes, bytearray)) else val.encode('utf8'))
        result = 0
        for index, this in enumerate(values):
            if index == 0: # first index has nothing to compare
                continue
            prev = values[index-1]              # use the index variable i to locate prev
            # Constant time string comparision, mitigates side channel attacks.
            if len(prev) != len(this):
                return False
            for _x, _y in zip(chk_bytes(prev), chk_bytes(this)):
                result |= _x ^ _y
        return result == 0

    def validate(self, secret_key :str):
        if not self.is_valid_scheme():
            logger.error('incompatible authorization scheme, expected "Authorization: HMAC ..."')
            return False
        if not self.is_valid_nonce():
            logger.error(f'bad nonce {self.nonce}')
            return False
        if not self.is_valid_timestamp():
            logger.error(f'jitter detected {self.ts}')
            return False
        if self.algorithm not in self.supported_algorithms.keys():
            logger.error(f'algorithm {self.algorithm} is not supported')
            return False

        digestmod = self.supported_algorithms.get(self.algorithm)
        # Sign HMAC using server-side secret
        digest = hmac.new(secret_key.encode('utf8'), self.canonical_string.encode('utf8'), digestmod).hexdigest()
        self.server_mac = digest
        # Compare server-side HMAC with client provided HMAC
        return hmac.compare_digest(digest, self.mac)
