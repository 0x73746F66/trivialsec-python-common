import importlib
from gunicorn.glogging import logging
from elasticsearch import Elasticsearch
from .config import config


logger = logging.getLogger(__name__)
__module__ = 'trivialsec.helpers.elasticsearch_adapter'
__models_module__ = importlib.import_module('trivialsec.models')

class Elasticsearch_Collection_Adapter:
    es = Elasticsearch(f"{config.elasticsearch.get('scheme')}{config.elasticsearch.get('host')}:{config.elasticsearch.get('port')}")

    def __init__(self, class_name, index, primary_key):
        self.es.indices.create(index=index, ignore=400)
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

    def search(self, search_filter):
        # res = es.search(index="test-index", query={"match_all": {}})
        # print("Got %d Hits:" % res['hits']['total']['value'])
        # for hit in res['hits']['hits']:
        #     print("%(timestamp)s %(author)s: %(text)s" % hit["_source"])
        return self

    def count(self, search_filter) -> int:
        return 0

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
    es = Elasticsearch(f"{config.elasticsearch.get('scheme')}{config.elasticsearch.get('host')}:{config.elasticsearch.get('port')}")

    def __init__(self, index, pk):
        self.es.indices.create(index=index, ignore=400)
        self.__index = index
        self.__pk = pk
        self.__cols = set()
        self._doc = None

    def get_doc(self) -> bool:
        return self._doc

    def hydrate(self) -> bool:
        primary_key = getattr(self, self.__pk)
        if primary_key is None:
            return False
        self._doc = self.es.get(index=self.__index, id=primary_key, ignore=404)
        if self._doc.get('_source', {}).get(self.__pk) != primary_key:
            return False
        for col in self.cols():
            if col.startswith('_'):
                continue
            setattr(self, col, self._doc['_source'].get(col))

        return True

    def exists(self) -> bool:
        primary_key = getattr(self, self.__pk)
        if primary_key is None:
            return False
        res = self.es.exists(index=self.__index, id=primary_key)
        return res.get('found', False)

    def persist(self, extra :dict = None) -> bool:
        doc = vars(self)
        del doc['_Elasticsearch_Document_Adapter__cols']
        if isinstance(extra, dict):
            doc = {**doc, **extra}
        res = self.es.index(index=self.__index, id=doc[self.__pk], body=doc)
        if res['_shards']['successful'] >= 1:
            return True
        return False

    def cols(self) -> list:
        self.__cols = list(vars(self).keys())
        return self.__cols

    def delete(self) -> bool:
        primary_key = getattr(self, self.__pk)
        if primary_key is None:
            return False
        res = self.es.delete(index=self.__index, id=primary_key, refresh=True)
        return res.get('result') == "deleted"
