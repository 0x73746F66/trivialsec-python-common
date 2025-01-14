import importlib
from .account_config import *
from .account import *
from .activity_log import *
from .apikey import *
from .cve import *
from .cwe import *
from .domain import *
from .feed import *
from .finding_detail import *
from .finding_note import *
from .finding import *
from .invitation import *
from .job_run import *
from .key_value import *
from .link import *
from .member_mfa import *
from .member import *
from .notification import *
from .plan_invoice import *
from .plan import *
from .project import *
from .role import *
from .security_alert import *
from .service_type import *
from .webhook import *

__module__ = 'trivialsec.models'

class UpdateTable:
    def __init__(self, class_name :str, column :str, value, hydrate_using :list):
        module = importlib.import_module(__module__)
        class_ = getattr(module, class_name)
        self.__cls = class_()
        self.__cls.hydrate(hydrate_using)
        self.class_name = class_name
        self.column = column
        self.value = value
        setattr(self.__cls, column, value)

    def setattr(self, attr :str, value):
        setattr(self.__cls, attr, value)

    def persist(self):
        return self.__cls.persist()

    def __str__(self):
        return str(self.__cls)

    def __repr__(self):
        return str(self)
