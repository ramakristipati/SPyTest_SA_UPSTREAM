import inspect
import sys
from collections import OrderedDict
from pyangbind.lib.serialise import pybindJSONDecoder
from pyangbind.lib.serialise import pybindIETFJSONEncoder
from pyangbind.lib.serialise import WithDefaults
from enum import Enum
from spytest import st
import six, copy, json
from utilities.common import get_current_test_id
from pytest import fixture

class NorthBoundApi(Enum):
    """Specifies the type of the north bound interface
    """
    REST  = 1
    GNMI  = 2
    KLISH = 3

class Operation(Enum):
    """Specifies the type of the north bound operation
    """
    CREATE    = 1
    REPLACE   = 2
    UPDATE    = 3
    DELETE    = 4
    SUBSCRIBE = 5
    REMOVE    = 6
    GET       = 7

rest_to_generic_op = {
    "post":  Operation.CREATE,
    "put":   Operation.REPLACE,
    "patch": Operation.UPDATE
}

gnmi_to_generic_op = {
    "update":    Operation.UPDATE,
    "replace":   Operation.REPLACE,
    "delete":    Operation.DELETE
}

def _addObj(obj, spec, val=None, start_index=0, state=True, config=True):
    """
    Helper method for buildOcObj
    """
    xpath = spec[1]
    keyword = spec[2]
    is_config = spec[4]
    xpathList = list(filter(None, xpath.split('/')))
    xpathList = xpathList[start_index:]
    ret_obj = None
    if not state:
        if not is_config:
            return ret_obj
    if not config:
        if is_config:
            return ret_obj
    total_elements = len(xpathList)
    for index, node in enumerate(xpathList):
        if index + 1 == total_elements:
            is_last_element = True
        else:
            is_last_element = False
        if node not in obj:
            obj[node] = OrderedDict()

        if not is_last_element:
            obj = obj[node]
        else:
            if keyword == "list":
                obj[node] = list()
                ret_obj = obj[node]
            elif keyword == "leaf" or keyword == "leaf-list" and val is not None:
                obj[node] = val

    return ret_obj


def _walk_obj(obj, target_obj, start_index=0, state=True, config=True):
    """
    Helper method for buildOcObj
    """
    listArr = []
    normalAttr = []
    for attr in inspect.getmembers(obj):
        if not attr[0].startswith('_') and not inspect.ismethod(attr[1]):
            if attr[0] in obj.attrs:
                if attr[1] is not None:
                    normalAttr.append(attr)
                    _addObj(target_obj, obj.attrs[attr[0]], attr[1], start_index, state, config)
            elif attr[0] in obj.listdict:
                if len(attr[1]) > 0:
                    listArr.append(attr)
    for attr in listArr:
        ret_obj = _addObj(target_obj, obj.listdict[attr[0]], None, start_index, state, config)
        if ret_obj is None:
            continue
        xpathList = list(
            filter(None, obj.listdict[attr[0]][1].split('/')))
        start_index = len(xpathList)
        for nested_obj_key in attr[1]:
            new_target_obj = OrderedDict()
            ret_obj.append(new_target_obj)
            _walk_obj(attr[1][nested_obj_key], new_target_obj, start_index, state, config)


def _getBind(obj, bindObj):
    """
    Helper method for buildOcObj
    """
    filledBindObj = pybindJSONDecoder.load_ietf_json(
        obj, None, None, obj=bindObj)
    return filledBindObj


def get_ui_op(dut, **kwargs):
    ui = NorthBoundApi.REST
    operation = Operation.UPDATE
    ui_type = st.get_ui_type(dut, **kwargs)
    if ui_type:
        ui_type = ui_type.lower()
        if ui_type == "klish":
            ui = NorthBoundApi.KLISH
        elif ui_type.startswith('rest-'):
            ui = NorthBoundApi.REST
            if ui_type not in ["rest-patch", "rest-put", "rest-post"]:
                st.log("Unknown Operation: {}, using Operation-UPDATE".format(ui_type))
                operation = Operation.UPDATE
            else:
                operation = ui_type.split('-')[1]
                operation = rest_to_generic_op[operation]
        elif ui_type == "rest":
            ui = NorthBoundApi.REST
            operation = Operation.UPDATE
        elif ui_type == "gnmi":
            ui = NorthBoundApi.GNMI
            operation = Operation.UPDATE
        elif ui_type.startswith('gnmi-'):
            ui = NorthBoundApi.GNMI
            if ui_type not in ["gnmi-replace", "gnmi-update"]:
                st.log("Unknown UI type: {}, Operation-UPDATE".format(ui_type))
                operation = Operation.UPDATE
            else:
                operation = ui_type.split('-')[1]
                operation = gnmi_to_generic_op[operation]
        else:
            ui = NorthBoundApi.REST
            operation = Operation.UPDATE
    else:
        ui = NorthBoundApi.REST
        operation = Operation.UPDATE

    kw_ui = kwargs.get('ui', None)
    kw_op = kwargs.get('operation', None)
    if kw_ui is not None:
        ui = kw_ui
    if kw_op is not None:
        operation = kw_op

    return ui, operation

def buildOcObj(obj, bindObj=None, state=True, config=True):
    """
    Converts message object to OC JSON (by default).
    If OC Bind class Obj is passed, then filled pyangBind Obj
    is returned
    """
    target_obj = OrderedDict()
    _walk_obj(obj, target_obj, 0, state, config)
    if bindObj is not None:
        return _getBind(target_obj, bindObj)
    else:
        return target_obj

class pybindCustomIETFJSONEncoder(pybindIETFJSONEncoder):


    @staticmethod
    def generate_yang_element(obj, flt=False, with_defaults=None, parent_namespace=None, depth=sys.maxsize,
                         content="all", fields_dict=None):
        """
          Convert a pyangbind class to a format which encodes to the IETF JSON
          specification. In this pybindCustomIETFJSONEncoder, 'identityref' elements
          are always represented with the namespace qualified form.
          Please refer https://datatracker.ietf.org/doc/html/rfc7951#section-6.8

          Modes of operation controlled by with_defaults:

            - None: skip data set to default values
            - WithDefaults.IF_SET: include all explicitly set data
            - Namespace of the parent node
            - Depth query param
            - Content query param
            - Field query param dictionary to keep the fields path nodes
          The implementation is based on draft-ietf-netmod-yang-json-07.
        """
        if depth == 1:
            return {}
        is_config = getattr(obj, "_is_config", None)
        if content != "all":
            if is_config and content == "nonconfig":
                return {}
            elif is_config is False and content == "config":
                return {}
        if fields_dict is not None:
            yang_name = getattr(obj, "_yang_name", None)
            if yang_name is not None:
                if yang_name in fields_dict:
                    fields_dict = fields_dict[yang_name]
                else:
                    return {}
        generated_by = getattr(obj, "_pybind_generated_by", None)
        if generated_by == "YANGListType":
            return [pybindCustomIETFJSONEncoder.generate_yang_element(i, flt=flt,
                with_defaults=with_defaults, depth=depth-1, fields_dict=fields_dict, content=content) for i in obj.itervalues()]
        elif generated_by is None:
            # This is an element that is not specifically generated by
            # pyangbind, so we simply serialise it how we would if it
            # were a scalar.
            return obj

        d = {}
        for element_name in obj._pyangbind_elements:
            element = getattr(obj, element_name, None)
            yang_name = getattr(element, "yang_name", None)
            yname = yang_name() if yang_name is not None else element_name
            if not element._namespace == parent_namespace:
            # if the namespace is different, then precede with the module name as per spec.
                yname = "%s:%s" % (element._defining_module, yname)

            generated_by = getattr(element, "_pybind_generated_by", None)
            if generated_by == "container":
                d[yname] = pybindCustomIETFJSONEncoder.generate_yang_element(element,
                              parent_namespace=element._namespace, flt=flt,
                              with_defaults=with_defaults, depth=depth-1,fields_dict=fields_dict, content=content)
                if not len(d[yname]):
                    del d[yname]
            elif generated_by == "YANGListType":
                d[yname] = [pybindCustomIETFJSONEncoder.generate_yang_element(i,
                              parent_namespace=element._namespace, flt=flt,
                              with_defaults=with_defaults, depth=depth-1, fields_dict=fields_dict, content=content)
                                for i in element.itervalues()]
                if not len(d[yname]):
                    del d[yname]
            else:
                tmpElement = None
                if with_defaults is None:
                    if flt and element._changed():
                        tmpElement = element
                    elif not flt:
                        tmpElement = element
                elif with_defaults == WithDefaults.IF_SET:
                    if element._changed() or element._default == element:
                        tmpElement = element

                if tmpElement is not None:
                    leaf_name = getattr(tmpElement, "_yang_name", None)
                    is_key = getattr(tmpElement, "_is_keyval", None)
                    if (is_key or fields_dict is None) or (leaf_name in fields_dict or len(fields_dict) == 0):
                        generated_by = getattr(tmpElement, "_pybind_generated_by", None)
                        if is_key is False:
                            is_config = getattr(tmpElement, "_is_config", None)
                            if content == "operational":
                                if is_config:
                                    continue
                                is_operational = True;
                                tmp_obj = tmpElement;
                                while tmp_obj is not None:
                                    if hasattr(tmp_obj, '_parent') is False:
                                        st.log("generate_yang_element: parent not found for the node:", tmp_obj)
                                        break;
                                    else:
                                        tmp_obj = tmp_obj._parent;
                                    #node_name = getattr(tmp_obj, "_yang_name", None)
                                    if "config" in tmp_obj._pyangbind_elements:
                                        config_elem = getattr(tmp_obj, "config", None)
                                        if element_name in config_elem._pyangbind_elements:
                                            st.log("generate_yang_element: node {} is not operational".format(leaf_name))
                                            is_operational = False
                                        break
                                    node_type = getattr(tmp_obj, "_pybind_generated_by", None)
                                    if node_type == "YANGListType":
                                        break
                                if is_operational is False:
                                    continue
                        if generated_by == "ReferencePathType" and len(tmpElement.__str__()) > 0:
                            path_parts = tmpElement._referenced_path.split("/")
                            leafRefNode = tmpElement
                            leafNode = tmpElement
                            for path in path_parts:
                                if path == "..":
                                    if hasattr(leafRefNode, '_parent'):
                                        leafRefNode = leafRefNode._parent
                                    else:
                                        break
                                else:
                                    leafRefNode = getattr(leafRefNode, path, None)
                            leafRefGen = getattr(leafRefNode, "_pybind_generated_by", None)
                            if leafRefGen == "RestrictedClassType" and leafRefNode._yang_type == "identityref" and len(leafNode.__str__()) > 0:
                                if leafNode.__str__() in leafRefNode._base_type._restriction_dict['dict_key']:
                                    ygModuleName = leafRefNode._base_type._restriction_dict['dict_key'][leafNode.__str__()]['@module']
                                    d[yname] = "%s:%s" % (ygModuleName, leafNode.__str__())
                                else:
                                    d[yname] = leafNode
                            else:
                                d[yname] = leafNode
                        elif generated_by == "RestrictedClassType" and tmpElement._yang_type == "identityref" and len(tmpElement.__str__()) > 0:
                            if tmpElement.__str__() in tmpElement._base_type._restriction_dict['dict_key']:
                                ygModuleName = tmpElement._base_type._restriction_dict['dict_key'][tmpElement.__str__()]['@module']
                                d[yname] = "%s:%s" % (ygModuleName, tmpElement.__str__())
                            else:
                                d[yname] = tmpElement
                        else:
                            d[yname] = tmpElement
        return d


class TargetInfo:
    def __init__(self, attr, path):
        self.attr = attr
        self.path = path


def resolve_targets(msg_obj, target_attr, target_path):
    """Returns the target_attr and target_path data as a list of TargetInfo objects.
    If the target_attr is a common propertry, it will be expanded into individual property names.
    """
    if target_attr is not None and target_path is not None:
        raise ValueError("target_attr and target_path are mutually exclusive")
    target_list = []
    if target_attr:
        if not isinstance(target_attr, list):
            target_attr_list = [target_attr]
        else:
            target_attr_list = target_attr
        attr_set = set()
        for t_attr in target_attr_list:
            if hasattr(msg_obj, "common_attr_dict") and t_attr is not None and t_attr.yang_path in msg_obj.common_attr_dict:
                for attr in msg_obj.common_attr_dict[t_attr.yang_path]:
                    if attr in msg_obj.attr_prop_dict:
                        attr_set.add(attr)
                        target_list.append(TargetInfo(msg_obj.attr_prop_dict[attr], None))
            if t_attr is not None and t_attr.yang_path not in attr_set and t_attr.yang_path in msg_obj.attr_prop_dict:
                attr_set.add(t_attr.yang_path)
                target_list.append(TargetInfo(msg_obj.attr_prop_dict[t_attr.yang_path], None))
    elif target_path:
        if not isinstance(target_path, list):
            target_path_list = [target_path]
        else:
            target_path_list = target_path
        for t_path in target_path_list:
            target_list.append(TargetInfo(None, t_path))
    if len(target_list) == 0:
        target_list.append(TargetInfo(None, None))
    return target_list

def remove_path(tree, path):
    this_part = path.pop(0)
    if len(path) == 0:
        try:
            del tree[this_part]
            return tree
        except KeyError:
            # ignore missing dictionary key
            pass
    else:
        try:
            tree[this_part] = remove_path(tree[this_part], path)
        except KeyError:
            pass
    return tree

def dumps(obj, indent=4, filter=True, skip_subtrees=[], select=False, mode="default",
          with_defaults=None, depth=sys.maxsize, fields_dict=None, content="all"):

    def lookup_subdict(dictionary, key):
        if not isinstance(key, list):
            raise AttributeError("keys should be a list")
        unresolved_dict = {}
        for k, v in six.iteritems(dictionary):
            if ":" in k:
                k = k.split(":")[1]
            unresolved_dict[k] = v

        if not key[0] in unresolved_dict:
            raise KeyError("requested non-existent key (%s)" % key[0])
        if len(key) == 1:
            return unresolved_dict[key[0]]
        current = key.pop(0)
        return lookup_subdict(dictionary[current], key)

    if not isinstance(skip_subtrees, list):
        raise AttributeError("the subtrees to be skipped should be a list")
    if mode == "ietf":
        if fields_dict is not None:
            yang_name = getattr(obj, "_yang_name", None)
            if yang_name is not None:
                fields_dict = {yang_name: fields_dict}
        # st.debug("dumps : generate_yang_element: depth: {}, content: {}, fields_dict: {}".format(depth, content, fields_dict))
        tree = pybindCustomIETFJSONEncoder.generate_yang_element(obj, flt=filter, with_defaults=with_defaults, depth=depth,
                                                            fields_dict=fields_dict, content=content)
        # st.debug("dumps: json encoder: generated yang data tree: {}".format(tree))
    else:
        tree = obj.get(filter=filter)
    for p in skip_subtrees:
        pp = p.split("/")[1:]
        # Iterate through the skip path and the object's own path to determine
        # whether they match, then skip the relevant subtrees.
        match = True
        trimmed_path = copy.deepcopy(pp)
        for i, j in zip(obj._path(), pp):
            # paths may have attributes in them, but the skip dictionary does
            # not, so we ensure that the object's absolute path is attribute
            # free,
            if "[" in i:
                i = i.split("[")[0]
            if not i == j:
                match = False
                break
            trimmed_path.pop(0)

        if match and len(trimmed_path):
            tree = remove_path(tree, trimmed_path)

    if select:
        key_del = []
        for t in tree:
            keep = True
            for k, v in six.iteritems(select):
                v = six.text_type(v)
                if mode == "default" or isinstance(tree, dict):
                    if keep and six.text_type(lookup_subdict(tree[t], k.split("."))) != v:
                        keep = False
                else:
                    # handle ietf case where we have a list and might have namespaces
                    if keep and six.text_type(lookup_subdict(t, k.split("."))) != v:
                        keep = False
            if not keep:
                key_del.append(t)
        if mode == "default" or isinstance(tree, dict):
            for k in key_del:
                if mode == "default":
                    del tree[k]
        else:
            for i in key_del:
                tree.remove(i)

    return json.dumps(tree, cls=pybindCustomIETFJSONEncoder, indent=indent)

@fixture
def report_error(request):
    marker = request.node.get_closest_marker("report_opts")
    if marker is None:
        data = {}
    else:
        data = marker.kwargs
    if "stop_on_error" not in data:
        data["stop_on_error"] = True
    if "collect_support" not in data:
        data["collect_support"] = False
    cache_name = "__{}".format(get_current_test_id())
    st.set_cache(cache_name, data)
    yield
    st.del_cache(cache_name)

def validate_response(message, method, success, result, target_attr, target_path, **kwargs):
    """Generates a message for report_fail
    method       Generic API name
    success      When False performs negative testing
    result       Response class instance
    target_attr  Target attribute requested
    target_path  Target path requested
    """
    report_error = False
    stop_on_error = False
    collect_support = False
    tc_cache = "__{}".format(get_current_test_id())
    cache = st.get_cache(tc_cache, default=None)
    if cache is not None and isinstance(cache, dict):
        report_error = True
        if "stop_on_error" in cache:
            stop_on_error = cache['stop_on_error']
        if "collect_support" in cache:
            collect_support = cache['collect_support']
    if "report_error" in kwargs:
        report_error = kwargs["report_error"]
    if "stop_on_error" in kwargs:
        stop_on_error = kwargs["stop_on_error"]
    if "collect_support" in kwargs:
        collect_support = kwargs["collect_support"]
    if report_error and success != result.ok():
        msg = get_report_fail_msg(message, method, result, target_attr, target_path)
        st.report("msg", msg, type="fail", support=collect_support, abort=stop_on_error)
    return result

def get_report_fail_msg(message, method, result, target_attr, target_path):
    """Generates a message for report_fail
    result       Response class instance
    target_attr  Target attribute requested
    target_path  Target path requested
    """
    msg = "{} test_step failed on Message: {}".format(method, message)
    if target_attr is not None:
        msg = msg + ", Target_attr:{}".format(target_attr)
    if target_path is not None:
        msg = msg + ", Target_path:{}".format(target_path)
    msg = msg + ", Status:{}".format(result.status)
    if result.message is not None and len(result.message) > 0:
        msg = msg + ", Message:{}".format(result.message)
    return msg

def get_custom_prop(base_class, value, yang_path, rest_path, gnmi_path, yang_type, enum_dict, **kwargs):
    class CustomProperty(base_class):
        def __new__(cls, val, yang_path, rest_path, gnmi_path, attr_name):
            default_val = val
            if (base_class is CustomList) and \
                (not isinstance(val, (list, tuple))) and \
                (val is not None):
                val = [val]
                default_val = val
            if val is None or val == "*" or isinstance(val, bool):
                if base_class == int:
                    default_val = 0
                elif base_class is CustomBoolean:
                    default_val = bool(val)
                elif base_class == str:
                    if val is True:
                        default_val = "True" #just setting, no significance
                    else:
                        default_val = ""
                elif base_class == float:
                    default_val = 0.0
                elif base_class is not CustomList:
                    assert False, "Unexpected type"

            obj = super().__new__(cls, default_val)
            obj.yang_type = yang_type
            obj.enum_dict = enum_dict
            obj.value = val
            obj._yang_path = yang_path
            obj._rest_path = rest_path
            obj._gnmi_path = gnmi_path
            obj._attr_name = attr_name
            return obj

        def __call__(self):
            return self._val

        def __eq__(self, other):
            return self._val == other or super().__eq__(other)

        def __bool__(self):
            if self._val:
                return True
            else:
                return False

        def __hash__(self):
            return hash(self._val)

        @property
        def attr_name(self):
            return self._attr_name

        @property
        def value(self):
            return self._val

        @value.setter
        def value(self, val):
            if self.enum_dict:
                if isinstance(self, list):
                    if isinstance(val, (list, tuple)):
                        self._val = [self.enum_dict[v] if v in self.enum_dict else val for v in val]
                    elif val is not None:
                        self._val = [self.enum_dict[val] if val in self.enum_dict else val]
                    else:
                        self._val = None
                    return
                elif val in self.enum_dict:
                    self._val = self.enum_dict[val]
                    return
            self._val = val

        @property
        def yang_type(self):
            return self._yang_type

        @yang_type.setter
        def yang_type(self, yang_type):
            self._yang_type = yang_type

        @property
        def yang_path(self):
            return self._yang_path

        @property
        def rest_path(self):
            return self._rest_path

        @property
        def gnmi_path(self):
            return self._gnmi_path

        def isValid(self):
            return self._val is not None

    return CustomProperty(value, yang_path=yang_path, rest_path=rest_path, gnmi_path=gnmi_path, attr_name=kwargs.get('attr_name', None))


class CustomList(list):
    def __init__(self, value, *args, **kwargs):
        if value is None:
            return # Do not call super as it will raise exception
        elif not isinstance(value, (list, tuple)):
            super().__init__([value])
        else:
            super().__init__(value)


class CustomBoolean(int):
    def __init__(self, value, *args, **kwargs):
        self.__value = bool(value)

    def __bool__(self):
        return self.__value

    __nonzero__ = __bool__

def get_audit_msg(dut, msg):
    msg = "[{}-{}] {}".format(st.get_device_alias(dut, True, True), dut, msg)
    return msg
