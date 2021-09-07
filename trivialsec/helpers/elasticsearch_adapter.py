import importlib
from gunicorn.glogging import logging
from elasticsearch import Elasticsearch
from .config import config


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers.elasticsearch_adapter'
__models_module__ = importlib.import_module('trivialsec.models')

class Elasticsearch_Collection_Adapter:
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
        res = self.es.search(index=self.__index, body={"query_string": {"query": query_string}}) # pylint: disable=unexpected-keyword-arg
        logger.debug(f"{res['hits']['total']['value']} Hits: {query_string}")
        class_ = getattr(__models_module__, self.__class_name)
        for hit in res['hits']['hits']:
            model = class_()
            for col, val in hit['_source'].items():
                setattr(model, col, val)
            self.__items.append(model)

        self.__index = 0
        return self

    def count(self, query_string :str) -> int:
        # query_string 'assigner:"Unknown" AND cve_id:"CVE-2021-39279"'
        res = self.es.search(index=self.__index, body={"query_string": {"query": query_string}}) # pylint: disable=unexpected-keyword-arg
        logger.debug(f"{res['hits']['total']['value']} Hits: {query_string}")
        return len(res['hits']['hits'])

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

class Elasticsearch_Document_Adapter:
    __hash__ = object.__hash__
    _id :str
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

    def get_doc(self) -> bool:
        return self._doc.get('_source') if isinstance(self._doc, dict) else None

    def hydrate(self, query_string :str = None) -> bool:
        self._doc = None
        if self.__pk is not None and query_string is None:
            primary_key = getattr(self, self.__pk)
            if primary_key is None:
                return False
            self._doc = self.es.get(index=self.__index, id=primary_key, ignore=404) # pylint: disable=unexpected-keyword-arg
            if self._doc['found'] is False:
                return False

        if query_string is not None:
            res = self.es.search(index=self.__index, body={"query_string": {"query": query_string}}) # pylint: disable=unexpected-keyword-arg
            logger.debug(f"{res['hits']['total']['value']} Hits: {query_string}")
            if len(res['hits']['hits']) == 1:
                self._doc = res['hits']['hits'][0]

        if not isinstance(self._doc, dict):
            return False

        self._id = self._doc.get('_id')
        for col in self.cols():
            if col.startswith('_'):
                continue
            setattr(self, col, self._doc.get('_source', {}).get(col))

        return True

    def exists(self, query_string :str = None) -> bool:
        # query_string 'assigner:"Unknown" AND cve_id:"CVE-2021-39279"'
        if self.__pk is not None:
            primary_key = getattr(self, self.__pk)
            if primary_key is None:
                return False
            res = self.es.exists(index=self.__index, id=primary_key, _source=True) # pylint: disable=unexpected-keyword-arg
            if res['found'] is True:
                self._doc = res
                self._id = res.get('_id')
                return True
        res = self.es.search(index=self.__index, body={"query_string": {"query": query_string}}) # pylint: disable=unexpected-keyword-arg
        logger.debug(f"{res['hits']['total']['value']} Hits: {query_string}")
        if len(res['hits']['hits']) == 1:
            self._doc = res['hits']['hits'][0]
            self._id = self._doc['_id']
            return True
        return False

    def persist(self, extra :dict = None) -> bool:
        doc = vars(self)
        if '_Elasticsearch_Document_Adapter__cols' in doc:
            del doc['_Elasticsearch_Document_Adapter__cols']
        if '_Elasticsearch_Document_Adapter__index' in doc:
            del doc['_Elasticsearch_Document_Adapter__index']
        if '_Elasticsearch_Document_Adapter__pk' in doc:
            del doc['_Elasticsearch_Document_Adapter__pk']
        if isinstance(extra, dict):
            doc = {**doc, **extra}
        doc_id = None if self.__pk is None else self.__pk
        res = self.es.index(index=self.__index, id=doc_id, body=doc)
        if res['_shards']['successful'] >= 1:
            return True
        return False

    def cols(self) -> list:
        self.__cols = list(vars(self).keys())
        return self.__cols

    def delete(self, doc_id = None) -> bool:
        doc_id = doc_id if self.__pk is None else getattr(self, self.__pk)
        if doc_id is None:
            return False
        res = self.es.delete(index=self.__index, id=doc_id, refresh=True) # pylint: disable=unexpected-keyword-arg
        return res.get('result') == "deleted"
