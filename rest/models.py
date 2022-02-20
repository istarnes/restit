import os
from django.conf import settings
from django.core.exceptions import FieldDoesNotExist
from hashids import Hashids
import hashlib
import string

from datetime import datetime, date, timedelta
from decimal import Decimal
TWOPLACES = Decimal(10) ** -2

from django.db import models
from django.apps import apps
get_model = apps.get_model

from django.http import Http404
from django.core.exceptions import ValidationError

import threading

from rest import helpers as rest_helpers
from rest.uberdict import UberDict
from rest import search
from rest.privpub import PrivatePublicEncryption

import importlib

GRAPH_HELPERS = UberDict()
GRAPH_HELPERS.restGet = None
GRAPH_HELPERS.get_request = None
GRAPH_HELPERS.views = None

ENCRYPTER_KEY_FILE = os.path.join(settings.ROOT, "config", "encrypt_key.pem")
ENCRYPTER = None
if os.path.exists(ENCRYPTER_KEY_FILE):
    ENCRYPTER = PrivatePublicEncryption(private_key_file=ENCRYPTER_KEY_FILE)

class RestError(Exception):
    def __init__(self, reason, code=None):
        self.reason = reason
        self.code = code

    def __repr__(self):
        return self.reason

class PermisionDeniedException(RestError):
    def __init__(self, reason="permission denied", code=401):
        self.reason = reason
        self.code = code

def requestHasPerms(request, perms, group=None):
    if not request.user.is_authenticated:
        return False, "auth required", 401
    if not hasattr(request, 'member'):
        request.member, request.group = request.user.__class__.getMemberGroup(request, False, False)
    if request.member.hasPerm(perms):
        return True, None, None
    if group is None and hasattr(request, "group"):
        group = request.group
    if group and request.member.hasGroupPerm(group, perms):
        return True, None, None
    return False, "permission denied", 402


class MetaDataBase(models.Model):
    class Meta:
        abstract = True

    category = models.CharField(db_index=True, max_length=32, default=None, null=True, blank=True)

    key = models.CharField(db_index=True, max_length=80)

    value_format = models.CharField(max_length=16)
    value = models.TextField()

    int_value = models.IntegerField(default=None, null=True, blank=True)
    float_value = models.IntegerField(default=None, null=True, blank=True)

    def setValue(self, value):
        self.value = "{}".format(value)
        if type(value) is int and value < 2147483647:
            self.value_format = "I"
            self.int_value = value
        elif type(value) is float:
            self.value_format = "F"
            self.float_value = value
        elif isinstance(value, list):
            self.value_format = "L"
            # self.value = ",".join(value)
        elif isinstance(value, dict):
            self.value_format = "O"
        elif type(value) in [str, str] and len(value) < 9 and value.isdigit():
            self.value_format = "I"
            self.int_value = value
        elif value in ["True", "true", "False", "false"]:
            self.value_format = "I"
            if value in ["True", "true"]:
                self.int_value = 1
            else:
                self.int_value = 0
        elif isinstance(value, bool):
            self.value_format = "I"
            if value:
                self.int_value = 1
            else:
                self.int_value = 0
        else:
            self.value_format = "S"

    def getStrictType(self, field_type):
        if type(self.value) is field_type:
            return self.value
        if field_type in [int, str, float, str]:
            return field_type(self.value)
        elif field_type is bool:
            return self.value in [True, 1, '1', 'y', 'Y', 'true']
        elif field_type in [date, datetime]:
            return rest_helpers.parseDate(self.value)
        return self.value

    def getValue(self, field_type=None):
        if field_type:
            return self.getStrictType(field_type)
        elif self.value_format == 'I':
            return self.int_value
        elif self.value_format == 'F':
            return self.float_value
        elif self.value_format in ["L", "O"] and self.value:
            try:
                return eval(self.value)
            except:
                pass
        return self.value

    def __unicode__(self):
        if self.category:
            return "{}.{}={}".format(self.category, self.key, self.value)
        return "{}={}".format(self.key, self.value)

    def __str__(self):
        if self.category:
            return "{}.{}={}".format(self.category, self.key, self.value)
        return "{}={}".format(self.key, self.value)

class MetaDataModel(object):
    def set_metadata(self, request, values=None):
        # this may get called before the model is saved
        if not self.id:
            self.save()

        if values is None:
            values = request
            request = None

        if not isinstance(values, dict):
            raise Exception("invalid metadata: {}".format(values))

        for key, value in list(values.items()):
            cat = None
            if "." in key:
                cat, key = key.split('.')
            self.setProperty(key, value, cat, request=request)

    def metadata(self):
        return self.getProperties()

    def removeProperties(self, category=None):
        # this will remove all properties
        # if category is not it will remove all properties
        self.properties.filter(category=category).delete()

    def getProperties(self, category=None):
        ret = {}
        for p in self.properties.all():
            if p.category:
                props = self.getFieldProps(p.category)
                if props.hidden:
                    continue
                if p.category not in ret or not isinstance(ret.get(p.category, None), dict):
                    ret[p.category] = {}
                props = self.getFieldProps("{}.{}".format(p.category, p.key))
                if props.hidden:
                    continue
                ret[p.category][p.key] = p.getValue()
            else:
                props = self.getFieldProps(p.key)
                if props.hidden:
                    continue
                ret[p.key] = p.getValue()
        if category is not None:
            if category in ret:
                return ret[category]
            return {}
        return ret

    def __initFieldProps(self):
        if not hasattr(self, "__field_props"):
            if hasattr(self.RestMeta, "METADATA_FIELD_PROPERTIES"):
                # this provides extra protection for metadata fields
                self.__field_props = self.RestMeta.METADATA_FIELD_PROPERTIES
            else:
                self.__field_props = None

    def getFieldProps(self, key):
        self.__initFieldProps()
        full_key = key
        category = None
        if "." in key:
            category, key = key.split('.')
        props = UberDict()
        if self.__field_props:
            if category and self.__field_props.get(category, None):
                cat_props = self.__field_props.get(category, None)
                if cat_props:
                    props.notify = cat_props.get("notify", None)
                    props.on_change_name = cat_props.get("on_change", None)
                    props.hidden = cat_props.get("hidden", False)
                    if props.on_change_name:
                        props.on_change = getattr(self, props.on_change_name, None)
            field_props = self.__field_props.get(full_key, None)
            if field_props:
                props.notify = field_props.get("notify", props.notify)
                props.requires = field_props.get("requires", None)
                props.hidden = field_props.get("hidden", False)
                on_change_name = field_props.get("on_change", None)
                if on_change_name:
                    on_change = getattr(self, on_change_name, None)
                    if on_change:
                        props.on_change = on_change
        return props

    def checkFieldPerms(self, full_key, props, request=None):
        if not props.requires:
            return True
        if not request or not request.member:
            return False
        if request.member.hasPermission(props.requires) or request.user.is_superuser:
            return True

        # this a unauthorized attempt to change field, log and throw exception
        if props.notify and request.member:
            subject = "permission denied changing protected '{}' field".format(full_key)
            msg = "permission denied changing protected field '{}'\nby user: {}\nfor: {}".format(
                    full_key,
                    request.user.username,
                    self
                )
            request.member.notifyWithPermission(props.notify, subject, msg, email_only=True)
        raise PermisionDeniedException(subject)

    def setProperties(self, data, category=None, request=None, using=None):
        for k,v in list(data.items()):
            self.setProperty(k, v, category, request=request, using=using)

    def setProperty(self, key, value, category=None, request=None, using=None):
        # rest_helpers.log_print("{}:{} ({})".format(key, value, type(value)))
        on_change = None
        if not using:
            using = getattr(self.RestMeta, "DATABASE", using)
        if not request:
            request = RestModel.getActiveRequest()
        self.__initFieldProps()

        if isinstance(value, dict):
            return self.setProperties(value, key)
        username = "root"
        if request and request.member:
            username = request.member.username
        prop = None

        if "." in key:
            category, key = key.split('.')
        if category:
            # delete any keys with this category name
            full_key = "{}.{}".format(category, key)
            # this deletes anything with the key that matches the category
            # this works because the category is stored not in key but category field
            # rest_helpers.log_print("deleting key={}".format(category))
            self.properties.filter(key=category).delete()
        else:
            full_key = key

        field_props = self.getFieldProps(full_key)
        if not self.checkFieldPerms(full_key, field_props, request):
            return False

        check_value = "{}".format(value)
        has_changed = False
        prop = self.properties.filter(category=category, key=key).last()
        old_value = None
        if prop:
            # existing property we need to make sure we delete
            old_value = prop.getValue()
            if value is None or value == "":
                prop.delete()
                has_changed = True
            else:
                has_changed = check_value != prop.value
                if not has_changed:
                    return
                prop.setValue(value)
                prop.save(using=using)
            if field_props.on_change:
                field_props.on_change(key, value, old_value, category)
        elif value is None or value == "":
            # do not create none or empty property
            return False
        else:
            has_changed = True
            PropClass = self.get_fk_model("properties")
            prop = PropClass(parent=self, key=key, category=category)
            prop.setValue(value)
            # rest_helpers.log_print(u"saving {}.{}".format(category, key))
            # rest_helpers.log_print(u"saving {} : {}".format(full_key, value))
            prop.save(using=using)

        if hasattr(self, "_recordRestChange"):
            self._recordRestChange("metadata.{}".format(full_key), old_value)

        if field_props.notify and request and request.member:
            notify = field_props.get("notify")
            msg = "protected field '{}' changed to '{}'\nby user: {}\nfor: {}".format(
                full_key,
                value,
                username,
                self
            )
            request.member.notifyWithPermission(notify, "protected '{}' field changed".format(full_key), msg, email_only=True)
        return has_changed

    def getProperty(self, key, default=None, category=None, field_type=None):
        try:
            if "." in key:
                category, key = key.split('.')
            return self.properties.get(category=category, key=key).getValue(field_type)
        except:
            pass
        return default

class RestValidationError(RestError):
    pass

class RestModel(object):
    class __RestMeta__:
        NO_SAVE_FIELDS = ["uuid", "id", "pk", "created", "modified"]
        NO_SHOW_FIELDS = ["password"]
        WHITELISTED = ["merchant", "group", "user", "member", "terminal"]

    class RestMeta:
        NO_SAVE_FIELDS = []
        SAVE_FIELDS = []
        GRAPHS = {}

    @staticmethod
    def generateUUID(*args, **kwargs):
        upper = kwargs.get("upper", True)
        max_length = kwargs.get("max_length", None)
        uuid = ""
        for key in args:
            if isinstance(key, float):
                key = str(float)
            if isinstance(key, int):
                uuid += Hashids().encrypt(key)
            if isinstance(key, str):
                uuid += rest_helpers.toString(hashlib.md5(rest_helpers.toBytes(key)).hexdigest())
        if len(uuid) > 125:
            uuid = uuid[:125]
        if max_length != None:
            uuid = uuid[:max_length]
        if upper:
            return uuid.upper()
        return uuid

    @classmethod
    def buildGraph(cls, name):
        # we need to build it
        if hasattr(cls.RestMeta, "GRAPHS"):
            graphs = cls.RestMeta.GRAPHS
            if name in graphs:
                graph = graphs[name]
            else:
                graph = {}
        else:
            graph = {}

        if "no_uscore" not in graph:
            graph["no_uscore"] = False

        no_show_fields = RestModel.__RestMeta__.NO_SHOW_FIELDS
        if hasattr(cls.RestMeta, "NO_SHOW_FIELDS"):
            no_show_fields = cls.RestMeta.NO_SHOW_FIELDS

        field_names = []
        for f in cls._meta.fields:
            if not f.name.endswith("_ptr"):
                if f.name not in no_show_fields:
                    field_names.append(f.name)

        if "graphs" in graph:
            if "recurse_into" not in graph:
                graph["recurse_into"] = []
            if "fields" in graph:
                graph["fields"] = graph["fields"]
            elif "fields" not in graph and "self" in graph["graphs"]:
                graph["fields"] = []
            else:
                graph["fields"] = field_names

            for field in graph["graphs"]:
                gname = graph["graphs"][field]
                size = None
                ForeignModel = None
                sort = None

                if field.startswith("generic__"):
                    if field not in graph["recurse_into"]:
                        graph["recurse_into"].append((field, gname))
                        continue

                if isinstance(gname, dict):
                    size = gname.get("size")
                    sort = gname.get("sort")
                    fm_name = gname.get("model")
                    gname = gname.get("graph")
                    if not gname:
                        gname = "default"
                    if fm_name:
                        a_name, m_name = fm_name.split(".")
                        ForeignModel = RestModel.getModel(a_name, m_name)

                if not field or field == "self":
                    # this means it is referencing self
                    foreign_graph = cls.buildGraph(gname)
                    for part in foreign_graph:
                        if part not in graph:
                            graph[part] = foreign_graph[part]
                        else:
                            for f in foreign_graph[part]:
                                if f not in graph[part]:
                                    graph[part].append(f)
                            # graph[part] += foreign_graph[part]
                    continue

                # print "get FK: {0}".format(field)
                if not ForeignModel:
                    ForeignModel = cls.get_fk_model(field)
                if not ForeignModel:
                    rest_helpers.log_print("no foreignkey: {0}".format(field))
                    continue
                # print ForeignModel
                # print graph["recurse_into"]
                # print graph["recurse_into"]

                if field not in graph["recurse_into"]:
                    graph["recurse_into"].append(field)
                # print ForeignModel
                # if not hasattr(ForeignModel, "getGraph"):
                # 	foreign_graph = {}
                # 	foreign_graph["fields"] = []
                # 	for f in ForeignModel._meta.fields:
                # 		if f.name not in RestModel.__RestMeta__.NO_SHOW_FIELDS:
                # 			foreign_graph["fields"].append(f.name)
                # 	print ForeignModel
                # 	print foreign_graph["fields"]
                # else:
                if not hasattr(ForeignModel, "getGraph"):
                    # print "NO getGraph"
                    continue
                # print "getting graph: {0} for {1}".format(gname, field)
                foreign_graph = ForeignModel.getGraph(gname)
                # print foreign_graph

                for part in ["fields", "recurse_into", "extra", "exclude"]:
                    if part not in foreign_graph:
                        continue
                    graph_part = foreign_graph[part]
                    if part not in graph:
                        graph[part] = []
                    root_part = graph[part]
                    for f in graph_part:
                        if type(f) is tuple:
                            f1, f2 = f
                            nfname = ("{0}.{1}".format(field, f1), f2)
                        elif graph["no_uscore"] and '_' in f:
                            f1, f2 = f, f.replace('_', '').split('.')[-1]
                            # print field
                            # print f2
                            nfname = ("{0}.{1}".format(field, f1), f2)
                        else:
                            nfname = "{0}.{1}".format(field, f)
                        if nfname not in root_part:
                            root_part.append(nfname)
            del graph["graphs"]

        if "fields" not in graph:
            if graph["no_uscore"]:
                graph["fields"] = []
                for f in field_names:
                    if "_" in f:
                        f1, f2 = f, f.lower().replace('_', '')
                        # print "noscore"
                        # print f1
                        # print f2
                        graph["fields"].append((f1, f2))
                    else:
                        graph["fields"].append(f)
            else:
                graph["fields"] = field_names

        if "no_uscore" in graph:
            del graph["no_uscore"]

        return graph

    @classmethod
    def ro_objects(cls):
        using = getattr(cls.RestMeta, "RO_DATABASE", None)
        if using is None:
            using = getattr(cls.RestMeta, "DATABASE", None)
        # if using is None:
        # 	if settings.DATABASES.get("readonly", None) != None:
        # 		using = "readonly"
        if using:
            return cls.objects.using(using)
        return cls.objects

    @classmethod
    def rw_objects(cls):
        using = getattr(cls.RestMeta, "DATABASE", None)
        if using:
            return cls.objects.using(using)
        return cls.objects

    def safeSave(self, **kwargs):
        using = getattr(self.RestMeta, "DATABASE", None)
        if using:
            return self.save(using=using, **kwargs)
        return self.save(**kwargs)

    @classmethod
    def getGraph(cls, name):
        graph_key = "_graph_{0}__".format(name)
        if hasattr(cls, graph_key):
            return getattr(cls, graph_key)

        if not hasattr(cls, "_lock__"):
            cls._lock__ = threading.RLock()

        # cls._lock__.acquire()
        # try:
        graph = cls.buildGraph(name)
        # print "-" * 80
        # print "SETTING GRAPH {0} FOR {1}".format(name, cls.__name__)
        # print graph
        setattr(cls, graph_key, graph)
        # print "." * 80
        # except:
        # 	pass
        # cls._lock__.release()
        return graph

    def toGraph(self, request=None, graph="basic"):
        RestModel._setupGraphHelpers()
        if not request:
            request = GRAPH_HELPERS.get_request()
        return GRAPH_HELPERS.restGet(request, self, return_httpresponse=False, **self.getGraph(graph))

    @classmethod
    def getActiveLogger(cls):
        return rest_helpers.getLogger(cls.getActiveRequest())

    @classmethod
    def getActiveMember(cls):
        request = cls.getActiveRequest()
        if request:
            return request.member
        return None

    @classmethod
    def getActiveRequest(cls):
        if not GRAPH_HELPERS.get_request:
            mw = importlib.import_module("rest.middleware")
            GRAPH_HELPERS.get_request = mw.get_request
        return GRAPH_HELPERS.get_request()

    @classmethod
    def getFromRequest(cls, request):
        key = cls.__name__.lower()
        key_p = "{0}_id".format(key)
        lookup_fields = [key, key_p]
        using = getattr(cls.RestMeta, "DATABASE", None)
        for field in lookup_fields:
            value = request.DATA.get(field)
            if value:
                if not using:
                    obj = cls.objects.filter(pk=value).first()
                else:
                    obj = cls.objects.using(using).filter(pk=value).first()
                if obj:
                    return obj
        lookup_fields = getattr(cls.RestMeta, "UNIQUE_LOOKUP", [])
        for field in lookup_fields:
            value = request.DATA.get(field)
            if value:
                q = {}
                q[field] = value
                if not using:
                    obj = cls.objects.filter(**q).first()
                else:
                    obj = cls.objects.using(using).filter(**q).first()
                if obj:
                    return obj
        return None

        value = request.DATA.get(key_p)
        if not value:
            value = request.DATA.get(key)
            if not value:
                return None
        if using:
            return cls.objects.using(using).filter(pk=value).first()
        return cls.objects.filter(pk=value).first()

    @classmethod
    def getFromPK(cls, pk):
        using = getattr(cls.RestMeta, "DATABASE", None)
        if using:
            return cls.objects.using(using).filter(pk=pk).first()
        return cls.objects.filter(pk=pk).first()

    @classmethod
    def restEncrypt(cls, data):
        if ENCRYPTER:
            return ENCRYPTER.encrypt(data)
        return data

    @staticmethod
    def restGetModel(app_name, model_name):
        return apps.get_model(app_name, model_name)

    @staticmethod
    def getModel(app_name, model_name):
        return apps.get_model(app_name, model_name)

    def restGetGenericModel(self, field):
        # called by the rest module to magically parse
        # a component that is marked genericrelation in a graph
        if not hasattr(self, field):
            rest_helpers.log_print("model has no field: {0}".format(field))
            return None

        name = getattr(self, field)
        if not name or "." not in name:
            return None
        a_name, m_name = name.split(".")
        model = RestModel.getModel(a_name, m_name)
        if not model:
            rest_helpers.log_print("GENERIC MODEL DOES NOT EXIST: {0}".format(name))
        return model

    def restGetGenericRelation(self, field):
        # called by the rest module to magically parse
        # a component that is marked genericrelation in a graph
        GenericModel = self.restGetGenericModel(field)
        if not GenericModel:
            return None
        key = getattr(self, "{0}_id".format(field))
        return GenericModel.rw_objects().filter(pk=key).first()

    @staticmethod
    def restGetModelDB(Model, default=None):
        if hasattr(Model, "RestMeta"):
            return getattr(Model.RestMeta, "DATABASE", default)
        return default

    @property
    def has_model_changed(self):
        if hasattr(self, "_changed__"):
            return len(self._changed__) > 0
        return False

    def saveFields(self, allow_null=True, **kwargs):
        """
        Helper method to save a list of fields
        """
        self._changed__ = UberDict()
        for key, value in list(kwargs.items()):
            if value is None and not allow_null:
                continue
            self.restSaveField(key, value)
        if len(self._changed__):
            self.save()

    def restSaveField(self, fieldname, value, has_fields=False, has_no_fields=False, using=None):
        if not hasattr(self, "_changed__"):
            self._changed__ = UberDict()

        if fieldname.startswith("_"):
            return
        if not hasattr(self, "_field_names__"):
            self._field_names__ = [f.name for f in self._meta.get_fields()]
        # print "saving field: {0} = {1}".format(fieldname, value)
        if fieldname in RestModel.__RestMeta__.NO_SAVE_FIELDS:
            return
        if has_no_fields and fieldname in self.RestMeta.NO_SAVE_FIELDS:
            return
        if has_fields and fieldname not in self.RestMeta.SAVE_FIELDS:
            return

        if fieldname.endswith("_id") and not self.get_field_type(fieldname):
            # django will have ForeignKeys with _id, we don't want that, on_delete=models.CASCADE
            fieldname = fieldname[:-3]
        setter = "set_{0}".format(fieldname)
        if hasattr(self, setter):
            getattr(self, setter)(value)
            return

        if fieldname in self._field_names__:
            # TODO check if it is a function
            if isinstance(value, models.Model):
                setattr(self, fieldname, value)
                self._changed__[fieldname] = True
                return
            ForeignModel = self.get_fk_model(fieldname)
            if ForeignModel and isinstance(value, dict):
                obj = getattr(self, fieldname, None)
                if obj is None:
                    obj = ForeignModel()
                if using is None:
                    using = self.restGetModelDB(self)
                obj.saveFromDict(None, value, using=using)
                # rest_helpers.log_print("{} vs {}".format(self._state.db, obj._state.db))
                # rest_helpers.log_print("saving FK to {} ({}.{}) - {}".format(fieldname, using, obj.pk, type(obj)), value)
                setattr(self, fieldname, obj)
                self._changed__[fieldname] = True
                return
            elif ForeignModel and value and (type(value) is int or value.isdigit()):
                # print "\tforeign model({2}) field: {0} = {1}".format(fieldname, value, ForeignModel.__class__.__name__)
                value = int(value)
                using = RestModel.restGetModelDB(ForeignModel)
                if using:
                    value = ForeignModel.objects.using(using).filter(pk=value).first()
                else:
                    value = ForeignModel.objects.filter(pk=value).first()
            elif ForeignModel and "MediaItem" in ForeignModel.__name__:
                if value:
                    self.saveMediaFile(value, fieldname, None, True)
                return
            elif ForeignModel and not value:
                value = None
            # maybe we could look for to_python here to make sure we have proper conversion
            # thinking mainly around datetimes from epoch values
            if not ForeignModel:
                # field_model, model, direct, mm = self._meta.get_field_by_name(fieldname)
                field_model = self._meta.get_field(fieldname)
                # hack to handle save datetime fields correctly from floats
                try:
                    if field_model and value != None:
                        field_model_name = field_model.__class__.__name__
                        if field_model_name == "DateTimeField":
                            value = rest_helpers.parseDateTime(value)
                            # value = datetime.fromtimestamp(float(value))
                        elif field_model_name == "DateField":
                            value = rest_helpers.parseDate(value, as_date=True)
                        elif field_model_name == "IntegerField":
                            value = int(value)
                        elif field_model_name == "FloatField":
                            value = float(value)
                        elif field_model_name == "CurrencyField":
                            value = Decimal(value).quantize(TWOPLACES)
                        elif field_model_name == "BooleanField":
                            if value in [True, 1, 'True', 'true', '1', 't', 'y', 'yes']:
                                value = True
                            else:
                                value = False
                except Exception:
                    return
            if hasattr(self, fieldname) and getattr(self, fieldname) != value:
                self._changed__[fieldname] = getattr(self, fieldname)
            setattr(self, fieldname, value)
        # else:
        # 	print "does not have field: {0}".format(fieldname)

    def saveFromRequest(self, request, **kwargs):
        if "files" not in kwargs:
            kwargs["files"] = request.FILES
        return self.saveFromDict(request, request.DATA, **kwargs)

    def _recordRestChange(self, fieldname, old_value):
        if not hasattr(self, "_changed__"):
            self._changed__ = UberDict()
        if "." in fieldname:
            fields = fieldname.split('.')
            root = self._changed__
            for f in fields[:-1]:
                if f not in root:
                    root[f] = UberDict()
                root = root[f]
            root[fields[-1]] = old_value
        else:
            self._changed__[fieldname] = old_value

    def saveFromDict(self, request, data, files=None, **kwargs):
        can_save = getattr(self.RestMeta, "CAN_SAVE", True)
        if not can_save:
            return self.restStatus(request, False, error="saving not allowed via rest for this model.")
        # check check for save permissions
        if request is None:
            request = RestModel.getActiveRequest()
            if request is None:
                request = UberDict(member=None, FILES=[])
        if hasattr(self, "onRestCanSave"):
            # this should throw an error
            self.onRestCanSave(request)
        is_new = self.id is None
        has_fields = hasattr(self.RestMeta, "SAVE_FIELDS") and len(self.RestMeta.SAVE_FIELDS)
        has_no_fields = hasattr(self.RestMeta, "NO_SAVE_FIELDS") and len(self.RestMeta.NO_SAVE_FIELDS)
        self._field_names__ = [f.name for f in self._meta.get_fields()]
        # fix for multidatabase support and using readonly db for get
        self._state.db = kwargs.get("using", self.restGetModelDB(self, "default"))
        auto_save_fields = getattr(self.RestMeta, "AUTO_SAVE", None)
        if auto_save_fields:
            rest_helpers.log_print(auto_save_fields)
            for field in auto_save_fields:
                rest_helpers.log_print(field)
                if isinstance(field, tuple):
                    m_field, req_field = field
                else:
                    m_field = field
                    req_field = field
                req_value = getattr(request, req_field, None)
                if request and req_value:
                    data[m_field] = req_value
            rest_helpers.log_print(data)
        self._changed__ = UberDict()
        if hasattr(self.RestMeta, "POST_SAVE_FIELDS"):
            post_save_fields = self.RestMeta.POST_SAVE_FIELDS
        else:
            post_save_fields = []
        using = kwargs.get("using", self.restGetModelDB(self))
        deferred = {}
        group_fields = {}
        for fieldname in data:
            # we allow override via kwargs
            value = data.get(fieldname)
            if "." in fieldname:
                gname = fieldname[:fieldname.find('.')]
                fname = fieldname[fieldname.find('.')+1:]
                setter = "set_{0}".format(gname)
                if hasattr(self, setter):
                    if gname not in group_fields:
                        group_fields[gname] = {}
                    group_fields[gname][fname] = value
                    continue
            if fieldname in post_save_fields or fieldname.startswith("metadata"):
                deferred[fieldname] = value
                continue
            if fieldname not in kwargs:
                self.restSaveField(fieldname, value, has_fields, has_no_fields, using=using)
        for key, value in list(kwargs.items()):
            if key in post_save_fields:
                deferred[fieldname] = value
                continue
            self.restSaveField(key, value, has_fields, has_no_fields, using=using)

        self.restSaveFiles(request, files)

        self.on_rest_pre_save(request)
        self.save(using=using)
        for key, value in list(deferred.items()):
            self.restSaveField(key, value, has_fields, has_no_fields, using=using)

        if len(deferred):
            self.save(using=using)

        # these setters are responsible for saving themselves
        for gname in group_fields:
            setter = "set_{0}".format(gname)
            getattr(self, setter)(request, group_fields[gname])

        if hasattr(self, "onSavedFromRequest"):
            self.onSavedFromRequest(request, **kwargs)
        elif not is_new:
            self.on_rest_saved(request)
        return self

    def restSaveFiles(self, request, files=None):
        if files is None:
            files = request.FILES
        for name in files:
            key = "upload__{0}".format(name)
            if hasattr(self, key):
                getattr(self, key)(files[name], name)
            else:
                ForeignModel = self.get_fk_model(name)
                if ForeignModel and ForeignModel.__name__ == "MediaItem":
                    rest_helpers.log_print("saving media file: {}".format(name))
                    self.saveMediaFile(files[name], name)

    def changesFromDict(self, data):
        deltas = []
        field_names = [f.name for f in self._meta.get_fields()]
        for key in data:
            if key not in field_names:
                continue
            # we allow override via kwargs
            value = data.get(key)

            # field_model, model, direct, mm = self._meta.get_field_by_name(key)
            field_model = self._meta.get_field(key)
            # hack to handle save datetime fields correctly from floats
            try:
                if field_model and value != None:
                    field_model_name = field_model.__class__.__name__
                    if field_model_name == "DateTimeField":
                        value = datetime.fromtimestamp(float(value))
                    elif field_model_name == "DateField":
                        value = rest_helpers.parseDate(value)
                    elif field_model_name == "IntegerField":
                        value = int(value)
                    elif field_model_name == "FloatField":
                        value = float(value)
                    elif field_model_name == "CurrencyField":
                        value = Decimal(value).quantize(TWOPLACES)
                if hasattr(self, key) and getattr(self, key) != value:
                    deltas.append(key)
            except:
                pass
        return deltas

    def copyFieldsFrom(self, obj, fields):
        for f in fields:
            if hasattr(self, f):
                setattr(self, f, getattr(obj, f))

    def saveMediaFile(self, file, name, file_name=None, is_base64=False, group=None):
        """
        Generic method to save a media file
        """
        if file_name is None:
            file_name = name
        MediaItem = RestModel.getModel("medialib", "MediaItem")
        # make sure we set the name base64_data
        if is_base64:
            mi = MediaItem(name=file_name, base64_data=file, group=group)
        elif type(file) in [str, str] and (file.startswith("https:") or file.startswith("http:")):
            mi = MediaItem(name=name, downloadurl=file, group=group)
        else:
            mi = MediaItem(name=name, newfile=file, group=group)
        mi.save()
        setattr(self, name, mi)
        self.save()
        return mi

    def updateLogModel(self, request, model):
        if not request:
            request = self.getActiveRequest()
        if not request or not hasattr(request, "setLogModel"):
            rest_helpers.log_print("request does not support setLogModel")
            return
        if not self.id:
            self.save()
        request.setLogModel(model, self.id)

    def on_rest_pre_get(self, request):
        pass

    def on_rest_get(self, request):
        # check view permissions
        perms = getattr(self.RestMeta, "VIEW_PERMS", None)
        if perms:
            # we need to check if this user has permission
            group_field = getattr(self.RestMeta, "GROUP_FIELD", "group")
            status, error, code = requestHasPerms(request, perms, getattr(self, group_field, None))
            if not status:
                return self.restStatus(request, False, error=error, error_code=code)
        graph = request.DATA.get("graph", "default")
        self.on_rest_pre_get(request)
        return self.restGet(request, graph)

    def on_rest_post(self, request):
        perms = getattr(self.RestMeta, "SAVE_PERMS", None)
        if perms:
            # we need to check if this user has permission
            group_field = getattr(self.RestMeta, "GROUP_FIELD", "group")
            status, error, code = requestHasPerms(request, perms, getattr(self, group_field, None))
            if not status:
                return self.restStatus(request, False, error=error, error_code=code)
        self.saveFromRequest(request)
        status_only = request.DATA.get("status_only", False, field_type=bool)
        if status_only:
            return self.restStatus(request, True)
        graph = request.DATA.get("graph", "default")
        return self.restGet(request, graph)

    def on_rest_pre_save(self, request, **kwargs):
        pass

    def on_rest_created(self, request):
        self.on_rest_saved(request)

    def on_rest_saved(self, request):
        pass

    def on_rest_delete(self, request):
        can_delete = getattr(self.RestMeta, "CAN_DELETE", False)
        if not can_delete:
            return self.restStatus(request, False, error="deletion not allowed via rest for this model.")
        perms = getattr(self.RestMeta, "SAVE_PERMS", None)
        if perms:
            # we need to check if this user has permission
            group_field = getattr(self.RestMeta, "GROUP_FIELD", "group")
            status, error, code = requestHasPerms(request, perms, getattr(self, group_field, None))
            if not status:
                return self.restStatus(request, False, error=error, error_code=code)
        self.delete()
        RestModel._setupGraphHelpers()
        return self.restStatus(request, True)

    @classmethod
    def restList(cls, request, qset, graph=None, totals=None, return_httpresponse=True):
        RestModel._setupGraphHelpers()
        sort = None
        if hasattr(cls.RestMeta, "DEFAULT_SORT"):
            sort = cls.RestMeta.DEFAULT_SORT
        if totals:
            fields = totals
            totals = {}
            for tf in fields:
                cls_method = "qset_totals_{}".format(tf)
                if hasattr(cls, cls_method):
                    totals[tf] = getattr(cls, cls_method)(qset, request)
        if not graph and request != None:
            graph = request.DATA.get("graph", "default")
        return GRAPH_HELPERS.restList(request, qset, sort=sort, totals=totals, return_httpresponse=return_httpresponse, **cls.getGraph(graph))

    @classmethod
    def toList(cls, qset, graph=None, totals=None, request=None):
        return cls.restList(request, qset, graph, totals, False)

    def restStatus(self, request, status, **kwargs):
        RestModel._setupGraphHelpers()
        return GRAPH_HELPERS.restStatus(request, status, **kwargs)

    def restGet(self, request, graph=None, as_dict=False):
        RestModel._setupGraphHelpers()
        if not request:
            request = self.getActiveRequest()
        if not graph and request:
            graph = request.DATA.get("graph", "default")
        elif not graph:
            graph = "default"
        return_response = not as_dict
        return GRAPH_HELPERS.restGet(request, self, return_httpresponse=return_response, **self.getGraph(graph))

    def toDict(self, graph=None):
        RestModel._setupGraphHelpers()
        return self.restGet(None, graph=graph, as_dict=True)

    @classmethod
    def on_rest_list_filter(cls, request, qset=None):
        # override on do any pre filters
        return cls.on_rest_list_perms(request, qset)

    @classmethod
    def on_rest_list_perms(cls, request, qset=None):
        if request.group:
            group_perms = getattr(cls.RestMeta, "LIST_PERMS_GROUP", None)
            if group_perms is None:
                group_perms = getattr(cls.RestMeta, "VIEW_PERMS", None)
            if group_perms and request.member:
                has_perm = request.member.hasGroupPerm(request.group, group_perms) or request.member.hasPerm(group_perms)
                if not has_perm:
                    return cls.objects.none()
            qset = cls.on_rest_filter_children(request, qset)
        else:
            all_perms = getattr(cls.RestMeta, "VIEW_PERMS", None)
            if all_perms:
                if not request.member.hasPerm(all_perms):
                    return cls.objects.none()
        return qset

    @classmethod
    def on_rest_filter_children(cls, request, qset=None):
        group_field = getattr(cls.RestMeta, "GROUP_FIELD", "group")
        parent_kinds = getattr(cls.RestMeta, "LIST_PARENT_KINDS", ["org"])
        if request.DATA.get("child_groups") or request.group.kind in parent_kinds:
            ids = request.group.getAllChildrenIds()
            ids.append(request.group.id)
            # to avoid future filtering issues remove group
            request.group = None
            request.DATA.remove(group_field)
            if group_field != "group":
                request.DATA.remove("group")
            q = {}
            q["{}_id__in".format(group_field)] = ids
            return qset.filter(**q)
        return qset

    @classmethod
    def on_rest_list_ready(cls, request, qset=None):
        # override on do any post filters
        return qset

    @classmethod
    def on_rest_date_filter(cls, request, qset=None):
        date_range_field = getattr(cls.RestMeta, "DATE_RANGE_FIELD", "created")
        date_range_default = getattr(cls.RestMeta, "DATE_RANGE_DEFAULT", None)
        if date_range_default != None:
            date_range_default = datetime.now() - timedelta(days=date_range_default)
            qset = rest_helpers.filterByDateRange(qset, request, start=date_range_default, end=datetime.now()+timedelta(days=1), field=date_range_field)
        else:
            qset = rest_helpers.filterByDateRange(qset, request, field=date_range_field)
        return qset

    @classmethod
    def on_rest_list(cls, request, qset=None):
        qset = cls.on_rest_list_query(request, qset)
        graph = request.DATA.get("graph", "list")
        format = request.DATA.get("format")
        if format:
            return cls.on_rest_list_format(request, format, qset)
        totals = request.DATA.getlist("totals", None)
        return cls.restList(request, qset, graph, totals)

    @classmethod
    def on_rest_list_query(cls, request, qset=None):
        cls._boundRest()
        request.rest_class = cls
        if qset is None:
            qset = cls.ro_objects().all()
        qset = cls.on_rest_list_filter(request, qset)
        qset = cls.filterFromRequest(request, qset)
        qset = cls.queryFromRequest(request, qset)
        qset = cls.searchFromRequest(request, qset)
        qset = cls.on_rest_date_filter(request, qset)
        qset = cls.on_rest_list_ready(request, qset)
        return qset

    @classmethod
    def on_rest_list_format(cls, request, format, qset):
        if format in ["summary", "summary_only"]:
            return cls.on_rest_list_summary(request, qset)
        if hasattr(cls.RestMeta, "FORMATS"):
            fields =  cls.RestMeta.FORMATS.get(format)
        else:
            no_show_fields = RestModel.__RestMeta__.NO_SHOW_FIELDS
            if hasattr(cls.RestMeta, "NO_SHOW_FIELDS"):
                no_show_fields = cls.RestMeta.NO_SHOW_FIELDS

            fields = []
            for f in cls._meta.fields:
                if not f.name.endswith("_ptr"):
                    if f.name not in no_show_fields:
                        fields.append(f.name)
        if fields:
            name = request.DATA.get("format_filename", None)
            format_size = request.DATA.get("format_size", 10000)
            if name is None:
                name = "{}.{}".format(cls.__name__.lower(), format)
            # print "csv size: {}".format(qset.count())
            sort = request.DATA.get("sort", getattr(cls.RestMeta, "DEFAULT_SORT", None))
            if sort:
                qset = qset.order_by(sort)
            cls._boundRest()
            return GRAPH_HELPERS.views.restCSV(request, qset, fields, name, format_size)

    @classmethod
    def on_rest_list_summary(cls, request, qset):
        if not hasattr(cls.RestMeta, "SUMMARY_FIELDS"):
            return cls.restList(request, qset, None)
        cls._boundRest()
        summary_info = getattr(cls.RestMeta, "SUMMARY_FIELDS")
        output = UberDict()
        output.count = qset.count()
        for key, value in list(summary_info.items()):
            if key == "sum":
                res = rest_helpers.getSum(qset, *value)
                if isinstance(res, dict):
                    output.update(res)
                else:
                    output[value[0]] = res
            elif key == "avg":
                for f in value:
                    output["avg_{}".format(f)] = rest_helpers.getAverage(qset, f)
            elif key == "max":
                for f in value:
                    output["max_{}".format(f)] = rest_helpers.getMax(qset, f)
            elif isinstance(value, dict):
                if "|" in key:
                    fields = key.split("|")
                    if len(fields) > 1:
                        lbl = fields[0]
                        action = fields[1]
                        field = None
                    if len(fields) > 2:
                        field = fields[2]
                else:
                    action = "count"
                    lbl = key
                    field = None
                act_qset = qset.filter(**value)
                if action == "count":
                    output[lbl] = act_qset.count()
                elif action == "sum":
                    output[lbl] = rest_helpers.getSum(act_qset, field)
                elif action == "avg":
                    output[lbl] = rest_helpers.getAverage(act_qset, field)
                elif action == "max":
                    output[lbl] = rest_helpers.getMax(act_qset, field)
        return GRAPH_HELPERS.restGet(request, output)

    @classmethod
    def on_rest_batch(cls, request, action):
        # this method is called when rest_batch='somme action'
        cls._boundRest()
        batch_ids = request.DATA.getlist("batch_ids", [])
        batch_id_field = request.DATA.get("batch_id_field", "pk")
        q = {}
        if batch_ids:
            q["{}__in".format(batch_id_field)] = batch_ids
        batch_query = request.DATA.get("batch_query", None)
        if batch_query:
            # we ignore ids when doing a query
            q.update(batch_query)
        if action == "delete":
            can_delete = getattr(cls.RestMeta, "CAN_DELETE", False)
            if not can_delete:
                return GRAPH_HELPERS.restStatus(request, False, error="deletion not allowed via rest for this model.")
            qset = cls.rw_objects().filter(**q)
            count = qset.delete()
            return GRAPH_HELPERS.restStatus(request, True, error="delete {} items".format(count))
        elif action == "update":
            qset = cls.rw_objects().filter(**q)
            update_fields = request.DATA.get(["batch_data", "batch_update"])
            if not isinstance(update_fields, dict):
                return GRAPH_HELPERS.restStatus(request, False, error="batch_update should be key/values")
            count = qset.update(**update_fields)
            return GRAPH_HELPERS.restStatus(request, True, error="updated {} items".format(count))
        elif action == "create":
            batch_data = request.DATA.getlist("batch_data", [])
            items = []
            exist = []
            for item in batch_data:
                try:
                    obj = cls.ro_objects().filter(**item).last()
                    if not obj:
                        obj.saveFromDict(request, item)
                    items.append(obj)
                except:
                    pass
            return GRAPH_HELPERS.restList(request, items)
        return GRAPH_HELPERS.restStatus(request, False, error="not implemented")

    @classmethod
    def on_rest_create(cls, request, pk=None):
        can_create = getattr(cls.RestMeta, "CAN_CREATE", True)
        if not can_create:
            return GRAPH_HELPERS.restStatus(request, False, error="creation not allowed via rest for this model.")

        if hasattr(cls.RestMeta, "REQUEST_DEFAULTS"):
            kv = {}
            for k, v in list(cls.RestMeta.REQUEST_DEFAULTS.items()):
                if hasattr(request, k):
                    value = getattr(request, k)
                    if value != None:
                        kv[v] = value
            obj = cls.createFromRequest(request, **kv)
        else:
            obj = cls.createFromRequest(request)
        obj.on_rest_created(request)
        graph = request.DATA.get("graph", "default")
        return obj.restGet(request, graph)

    @classmethod
    def _boundRest(cls):
        RestModel._setupGraphHelpers()

    @staticmethod
    def _setupGraphHelpers():
        if not GRAPH_HELPERS.views:
            views = importlib.import_module("rest.views")
            GRAPH_HELPERS.views = views
            GRAPH_HELPERS.restNotFound = views.restNotFound
            GRAPH_HELPERS.restStatus = views.restStatus
            GRAPH_HELPERS.restList = views.restList
            GRAPH_HELPERS.restGet = views.restGet
        if not GRAPH_HELPERS.get_request:
            mw = importlib.import_module("rest.middleware")
            GRAPH_HELPERS.get_request = mw.get_request

    @classmethod
    def get_rest_help(cls):
        output = UberDict()
        if cls.__doc__:
            output.doc = cls.__doc__.rstrip()
        else:
            output.doc = ""
        output.model_name = cls.__name__
        output.fields = cls.rest_getQueryFields(True)
        output.graphs = {}
        if hasattr(cls, "RestMeta"):
            output.graph_names = list(getattr(cls.RestMeta, "GRAPHS", {}).keys())
            for key in output.graph_names:
                output.graphs[key] = cls.getGraph(key)
            output.no_show_fields = getattr(cls.RestMeta, "NO_SHOW_FIELDS", [])
            output.no_save_fields = getattr(cls.RestMeta, "NO_SAVE_FIELDS", [])
            output.search_fields = getattr(cls.RestMeta, "SEARCH_FIELDS", [])
        return output

    @classmethod
    def on_rest_request(cls, request, pk=None):
        # check if model id is in post
        request.rest_class = cls
        cls._boundRest()
        if not pk:
            pk_fields = []
            key = cls.__name__.lower()
            key_p = "{0}_id".format(key)
            pk_fields.append(key_p)
            # check if the cls has a field with the class name, (causes conflict)
            if not cls.get_field_type(key):
                pk_fields.append(key)
            pk = request.DATA.get(pk_fields, None, field_type=int)
        # generic rest request handler
        if pk:
            using = getattr(cls.RestMeta, "RO_DATABASE", None)
            if using is None:
                using = getattr(cls.RestMeta, "DATABASE", None)
            if using:
                obj = cls.objects.using(using).filter(pk=pk).last()
            else:
                obj = cls.objects.filter(pk=pk).last()
            if not obj:
                return GRAPH_HELPERS.views.restNotFound(request)
            if request.method == "GET":
                return obj.on_rest_get(request)
            elif request.method == "POST":
                return obj.on_rest_post(request)
            elif request.method == "DELETE":
                return obj.on_rest_delete(request)
            return GRAPH_HELPERS.views.restNotFound(request)

        if request.method == "GET":
            return cls.on_rest_list(request)
        elif request.method == "POST":
            if request.DATA.get("rest_batch"):
                return cls.on_rest_batch(request, request.DATA.get("rest_batch"))
            return cls.on_rest_create(request)
        return GRAPH_HELPERS.views.restNotFound(request)

    @classmethod
    def searchFromRequest(cls, request, qset):
        '''returns None if not foreignkey, otherswise the relevant model'''
        search_fields = getattr(cls.RestMeta, "SEARCH_FIELDS", None)
        search_terms = getattr(cls.RestMeta, "SEARCH_TERMS", None)
        q = request.DATA.get(["search", "q"])
        if q:
            sq = search.get_query(q, search_fields, search_terms)
            if sq:
                qset = qset.filter(sq)
        return qset

    @classmethod
    def rest_getWHITELISTED(cls):
        if hasattr(cls.RestMeta, "WHITELISTED"):
            return cls.RestMeta.WHITELISTED
        return cls.__RestMeta__.WHITELISTED

    @classmethod
    def rest_getQueryFields(cls, detailed=False):
        field_names = []
        all_fields = True
        if hasattr(cls.RestMeta, "QUERY_FIELDS"):
            field_names = cls.RestMeta.QUERY_FIELDS
            all_fields = "all_fields" in field_names

        if all_fields:
            for f in cls._meta.fields:
                if not f.name.endswith("_ptr") or f in cls.rest_getWHITELISTED():
                    field_names.append(f.name)
            if issubclass(cls, MetaDataModel):
                if detailed:
                    field_names.append("metadata")
                else:
                    field_names.append("properties__key")
                    field_names.append("properties__value")
        if detailed:
            output = []
            for f in field_names:
                if f == "metadata":
                    t = "MetaData"
                    fm = None
                else:
                    t = cls.get_field_type(f)
                    fm = cls.get_fk_model(f)
                info = {}
                info["name"] = f
                info["type"] = t
                if fm:
                    info["model"] = "{}.{}".format(fm._meta.app_label, fm.__name__)
                try:
                    fd = cls._meta.get_field(f)
                    if fd.choices:
                        info["choices"] = fd.choices
                    if fd.help_text:
                        info["help"] = fd.help_text()
                except:
                    pass
                output.append(info)
            return output
        return field_names

    @classmethod
    def filterFromRequest(cls, request, qset):
        '''returns None if not foreignkey, otherswise the relevant model'''
        field_names = cls.rest_getQueryFields()
        q = {}

        # check for customer filer
        filter = request.DATA.get("filter")
        # filter must be a dictionary
        if filter:
            """
            we can do customer filters but the name must be a allowed field
            and can only be one level deep ie no double "__" "group__member__owner"
            html select:
                name: "user_filter"
                field: "filter"
                options: [
                    {
                        label: "Staff Only",
                        value: "is_staff:1"
                    },
                    {
                        label: "Online",
                        value: "is_online:1"
                    },
                    {
                        label: "Online",
                        value: "is_online:1"
                    },
                ]
            """
            if not isinstance(filter, dict):
                filters = filter.split(';')
                filter = {}
                for f in filters:
                    if ":" in f:
                        k, v = f.split(':')
                        if v in ["true", "True"]:
                            v = True
                        elif v in ["false", "False"]:
                            v = False
                        filter[k] = v
            now = datetime.now()
            # rest_helpers.log_print(field_names)
            for key in filter:
                name = key.split('__')[0]
                value = filter[key]
                if name in field_names and value != '__':
                    if isinstance(value, str) and ':' in value and value.startswith('__'):
                        k, v = value.split(':')
                        key = key + k.strip()
                        value = v.strip()
                    if key.endswith("__in") and ',' in value:
                        if value.startswith("["):
                            value = value[1:-1]
                        value = value.split(',')
                    elif value in ["true", "True"]:
                        value = True
                    elif value in ["false", "False"]:
                        value = False
                    if isinstance(value, str) and "(" in value and ")" in value:
                        # this is a special function call
                        # rest_helpers.log_print(value)
                        if value.startswith("days("):
                            spos = value.find("(")+1
                            epos = value.find(")")
                            # rest_helpers.log_print(int(value[spos:epos]))
                            value = now + timedelta(days=int(value[spos:epos]))
                            # rest_helpers.log_print(now)
                            # rest_helpers.log_print(value)
                        elif value.startswith("hours("):
                            spos = value.find("(")+1
                            epos = value.find(")")
                            value = now + timedelta(hours=int(value[spos:epos]))
                        elif value.startswith("minutes("):
                            spos = value.find("(")+1
                            epos = value.find(")")
                            value = now + timedelta(minutes=int(value[spos:epos]))
                        elif value.startswith("seconds("):
                            spos = value.find("(")+1
                            epos = value.find(")")
                            value = now + timedelta(seconds=int(value[spos:epos]))
                        else:
                            continue
                    if key.count('__') <= 4:
                        q[key] = value
                else:
                    rest_helpers.log_print("filterFromRequest: invalid field: {} or {}".format(name, key))
        if q:
            rest_helpers.log_print(q)
            qset = qset.filter(**q)
        return qset

    @classmethod
    def queryFromRequest(cls, request, qset):
        '''returns None if not foreignkey, otherswise the relevant model'''
        field_names = cls.rest_getQueryFields()
        # group_field = getattr(self.RestMeta, "GROUP_FIELD", "group")
        # elif fn in ["group", "merchant"]: should change to group_field
        q = {}
        for fn in field_names:
            v = None
            if fn in cls.rest_getWHITELISTED():
                if fn in ["user", "member"]:
                    Member = RestModel.getModel("account", "Member")
                    v = Member.getFromRequest(request)
                elif fn == "terminal":
                    Terminal = ForeignModel = cls.get_fk_model(fn)
                    # Terminal = RestModel.getModel("payauth", "Terminal")
                    if Terminal:
                        tid = request.DATA.get("tid")
                        if tid:
                            v = Terminal.ro_objects().filter(tid=tid).last()
                        else:
                            v = Terminal.getFromRequest(request)
                    else:
                        v = request.DATA.get(fn)
                elif fn in ["group", "merchant"]:
                    v = request.DATA.get(fn)
                    if not v:
                        if request.group:
                            v = request.group
                        elif getattr(request, "terminal", None):
                            v = request.terminal.merchant
            elif fn == "start":
                # this is a reserved field
                # TODO internally change start to _start_
                continue
            else:
                v = request.DATA.get(fn)
            if v is None:
                continue
            if (isinstance(v, str) or isinstance(v, str)) and ',' in v:
                v = [a.strip() for a in v.split(',')]
                q["{}__in".format(fn)] = v
            if isinstance(v, list):
                q["{}__in".format(fn)] = v
            elif v != None:
                q[fn] = v
        if q:
            # rest_helpers.log_print("queryFromRequest: {}".format(q))
            qset = qset.filter(**q)
        return qset

    @classmethod
    def createFromRequest(cls, request, **kwargs):
        obj = cls()
        return obj.saveFromRequest(request, files=request.FILES, __is_new=True, **kwargs)

    @classmethod
    def createFromDict(cls, request, data, **kwargs):
        obj = cls()
        return obj.saveFromDict(request, data, __is_new=True, **kwargs)

    @classmethod
    def get_field_type(cls, fieldname):
        '''returns None if not foreignkey, otherswise the relevant model'''
        for field in cls._meta.fields:
            if fieldname == field.name:
                return field.get_internal_type()
        return None

    @classmethod
    def get_fk_model(cls, fieldname):
        '''returns None if not foreignkey, otherswise the relevant model'''
        try:
            field = cls._meta.get_field(fieldname)
            return field.related_model
        except:
            return None
