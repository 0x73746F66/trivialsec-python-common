import importlib
from gunicorn.glogging import logging
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
from .config import config


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers.elasticsearch_adapter'
__models_module__ = importlib.import_module('trivialsec.models')


class Indexes(object):
    cves = "cves"
    cwes = "cwes"
    domains = "domains"
    domaintools = "domaintools"
    domaintools_reputation = "domaintools-reputation"
    domaintools_hosting_history = 'domaintools-hosting-history'
    whoisxmlapi_brand_alert = "whoisxmlapi-brand-alert"
    whoisxmlapi_reputation = "whoisxmlapi-reputation"
    x509 = "x509"
    domainsdb = 'domainsdb'
    hibp_monitor = 'hibp-domain-monitor'
    hibp_breaches = 'hibp-breaches'
    safe_browsing = 'safe-browsing'
    phishtank = 'phishtank'
    shodan_honeyscore = 'shodan-honeyscore'
    project_honeypot = 'project-honeypot'

    @staticmethod
    def create():
        con = Elasticsearch(
            config.elasticsearch.get('hosts'),
            http_auth=(config.elasticsearch.get('user'), config.elasticsearch_password),
            scheme=config.elasticsearch.get('scheme'),
            port=config.elasticsearch.get('port'),
        )
        for index in vars(Indexes):
            if index.startswith('_'):
                continue
            con.indices.create(index=getattr(Indexes, index), ignore=400) # pylint: disable=unexpected-keyword-arg

class ElasticsearchCollectionAdapter:
    es = Elasticsearch(
        config.elasticsearch.get('hosts'),
        http_auth=(config.elasticsearch.get('user'), config.elasticsearch_password),
        scheme=config.elasticsearch.get('scheme'),
        port=config.elasticsearch.get('port'),
    )

    def __init__(self, class_name, index, primary_key = None):
        self.__class_name = class_name
        self.__index = index
        self.__pk = primary_key
        self.__index = 0
        self.__items = []

    def _load_items(self, results :list):
        class_ = getattr(__models_module__, self.__class_name)
        for result in results:
            model = class_()
            for col, val in result.items():
                setattr(model, col, val)
            self.__items.append(model)
        self.__index = 0

    def search(self, query_string :str):
        res = self.es.search(index=self.__index, body={'query': {"query_string": {"query": query_string}}})
        logger.debug(f"{res['hits']['total']['value']} Hits: {query_string}")
        class_ = getattr(__models_module__, self.__class_name)
        for hit in res.get('hits', []).get('hits', []):
            model = class_()
            for col, val in hit['_source'].items():
                setattr(model, col, val)
            self.__items.append(model)

        self.__index = 0
        return self

    def count(self, query_string :str) -> int:
        res = self.es.search(index=self.__index, body={'query': {"query_string": {"query": query_string}}})
        logger.debug(f"count {type(self)} query_string returned {len(res.get('hits', []).get('hits', []))} Hits\n{query_string}")
        return len(res.get('hits', []).get('hits', []))

    def set_items(self, items :list):
        self.__items = items
        self.__index = 0
        return self

    def __iter__(self):
        return self

    def __len__(self):
        return len(self.__items)

    def __next__(self):
        try:
            result = self.__items[self.__index]
        except IndexError as err:
            self.__index = 0
            raise StopIteration from err
        self.__index += 1
        return result

    def __getitem__(self, item):
        return self.__items[item]

    def to_list(self):
        return self.__items

class ElasticsearchDocumentAdapter:
    __hash__ = object.__hash__
    _id = None
    _doc = None
    es = Elasticsearch(
        config.elasticsearch.get('hosts'),
        http_auth=(config.elasticsearch.get('user'), config.elasticsearch_password),
        scheme=config.elasticsearch.get('scheme'),
        port=config.elasticsearch.get('port'),
    )

    def __init__(self, index, primary_key = None):
        self.__index = index
        self.__pk = primary_key
        self.__cols = set()

    def __repr__(self):
        ret = {
            col: getattr(self, col)
            for col in self.cols()
            if not col.startswith('_')
        }

        return repr(ret)

    def get_doc(self):
        return self._doc.get('_source') if isinstance(self._doc, dict) else None

    def get_id(self):
        doc_id = self._id
        if doc_id is None and self.__pk is not None:
            doc_id = getattr(self, self.__pk)
        return doc_id

    def set_id(self, doc_id) -> bool:
        res = self.es.exists(index=self.__index, id=doc_id, _source=False) # pylint: disable=unexpected-keyword-arg
        if res is True:
            self._id = doc_id
            return True
        return False

    def hydrate(self, query_string :str = None) -> bool:
        found = False
        self._doc = None
        if self._id is not None:
            logger.debug(f'hydrate {type(self)} trying _id')
            self._doc = self.es.get(index=self.__index, id=self._id, ignore=404) # pylint: disable=unexpected-keyword-arg
            found = self._doc['found']

        if self.__pk is not None and found is False:
            logger.debug(f'hydrate {type(self)} trying primary_key')
            primary_key = getattr(self, self.__pk)
            if primary_key is None:
                logger.error(f'hydrate {type(self)} primary_key is None')
                return False
            self._doc = self.es.get(index=self.__index, id=primary_key, ignore=404) # pylint: disable=unexpected-keyword-arg
            found = self._doc.get('found', False)

        if query_string is not None and found is False:
            logger.debug(f'hydrate {type(self)} trying query_string')
            res = self.es.search(index=self.__index, body={'query': {"query_string": {"query": query_string}}}, ignore=404) # pylint: disable=unexpected-keyword-arg
            if len(res.get('hits', []).get('hits', [])) != 1:
                logger.error(f"hydrate {type(self)} query_string returned {len(res.get('hits', []).get('hits', []))} Hits, expected 1\n{query_string}")
                return False
            self._doc = res.get('hits', []).get('hits', [])[0]
            found = True

        if not isinstance(self._doc, dict):
            logger.error(f'hydrate {type(self)} _doc is misssing')
            return False

        self._id = self._doc.get('_id')
        for col in self.cols():
            if col.startswith('_'):
                continue
            setattr(self, col, self._doc.get('_source', {}).get(col))

        return found

    def exists(self, query_string :str = None) -> bool:
        found = False
        try:
            if self._id is not None:
                found = self.es.exists(index=self.__index, id=self._id, _source=False) # pylint: disable=unexpected-keyword-arg

            if self.__pk is not None and found is False:
                primary_key = getattr(self, self.__pk)
                if primary_key is not None:
                    found = self.es.exists(index=self.__index, id=primary_key, _source=False) # pylint: disable=unexpected-keyword-arg
                    if found is True:
                        self._id = primary_key

            if query_string is not None and found is False:
                logger.debug(f"index {self.__index} query_string {query_string}")
                res = self.es.search(index=self.__index, body={'query': {"query_string": {"query": query_string}}})
                logger.debug(f"{res['hits']['total']['value']} Hits: {query_string}")
                if len(res.get('hits', []).get('hits', [])) != 1:
                    logger.error(f"exists {type(self)} query_string returned {len(res.get('hits', []).get('hits', []))} Hits, expected 1\n{query_string}")
                    return False
                self._id = res.get('hits', []).get('hits', [])[0]['_id']
                found = True
        except NotFoundError:
            pass
        except Exception as ex:
            logger.exception(ex)

        return found

    def persist(self, extra :dict = None) -> bool:
        doc_id = self.get_id()
        doc = {
            col: getattr(self, col)
            for col in vars(self).keys()
            if not col.startswith('_')
        }

        if isinstance(extra, dict):
            doc = {**doc, **extra}
        res = self.es.index(index=self.__index, id=doc_id, body=doc)
        if res['_shards']['successful'] >= 1:
            self._doc = {'_source': doc}
            self._id = res['_id']
            return True
        logger.error(f'persist {type(self)} {res.__dict__}')
        return False

    def cols(self) -> list:
        self.__cols = list(vars(self).keys())
        return self.__cols

    def delete(self) -> bool:
        doc_id = self.get_id()
        if doc_id is None:
            return False
        res = self.es.delete(index=self.__index, id=doc_id, refresh=True) # pylint: disable=unexpected-keyword-arg
        return res.get('result') == "deleted"
