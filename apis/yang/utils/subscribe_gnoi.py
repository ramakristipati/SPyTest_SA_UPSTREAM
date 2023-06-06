##
# This file defines utility types and functions to invoke the subscription
# related gNOI APIs and verify the responses.
#

from apis.yang.codegen.gnoi_service import GnoiService
from apis.yang.codegen.gnoi_rpc import GnoiRpc
from apis.yang.codegen.gnoi_bindings.sonic_debug_pb2 import SubscribePreferencesReq
from google.protobuf.json_format import MessageToDict
from grpc import StatusCode, RpcError
from spytest import st


class Pref(object):
    '''Pref object holds expected subscribe preferences for a path or a path_prefix.
    Similar to the protobuf message SubscribePreference; but each attribute can be set
    to None - to ignore them during verification.'''

    def __init__(self, path, onchange_supported=None, onchange_preferred=None,
                 wildcard_supported=None, min_interval=None):
        self.path, self.path_prefix = (None, path[:-1]) if path.endswith("*") else (path, None)
        self.on_change_supported = onchange_supported
        self.on_change_preferred = onchange_preferred
        self.wildcard_supported = wildcard_supported
        self.min_sample_interval = None if min_interval is None else min_interval*1000000000

    def match(self, msg):
        if self.path_prefix is not None and not msg.path.startswith(self.path_prefix):
            return False
        return _matches(msg.path, self.path) and \
            _matches(msg.on_change_supported, self.on_change_supported) and \
            _matches(msg.on_change_preferred, self.on_change_preferred) and \
            _matches(msg.wildcard_supported, self.wildcard_supported) and \
            _matches(msg.min_sample_interval, self.min_sample_interval)

    def __str__(self):
        return "{}".format(self.__dict__)


def verify_preferences(dut,
                       paths, include_subpaths=None, onchange_supported=None,
                       expect_status=StatusCode.OK,
                       expect_count=None,
                       expect_prefs=None):
    '''Invokes GetSubscribePreferences gNOI RPC with given paths and verifies the responses.'''
    if isinstance(onchange_supported, bool):
        onchange_supported = "TRUE" if onchange_supported else "FALSE"
    req = SubscribePreferencesReq(
        path=paths if isinstance(paths, (list, set, tuple)) else [paths],
        include_subpaths=include_subpaths,
        on_change_supported=onchange_supported)

    svc = GnoiService(proto="sonic_debug", name="Debug")
    rpc = GnoiRpc(name="GetSubscribePreferences", request=req)
    result = svc.execute2(dut, rpc, verify=False)
    if not result.ok():
        st.report_fail("msg", "GetSubscribePreferences failed: " + result.message)

    expect_prefs = PreferenceMatcher(expect_prefs)
    expect_status = as_grpc_status(expect_status)
    status = StatusCode.OK
    count = 0

    st.log("Expected status={}, message count={}".format(expect_status, expect_count))
    st.log("Expected preferences:\n" + str(expect_prefs))

    try:
        for r in result.data:
            count += 1
            st.log("Received message #{}: {}".format(count, pb_dict(r)))
            if not expect_prefs.matches(r):
                st.report_fail("msg", "Message #{} does not match expected values".format(count))
    except RpcError as err:
        status = err.code()  #pylint: disable=no-member
        st.log("Received RpcError: " + str(err))

    if not _matches(status, expect_status):
        st.report_fail("msg", "Expected status {}; got {}".format(expect_status, status))
    if not _matches(count, expect_count):
        st.report_fail("msg", "Expected {} messages; got {}".format(expect_count, count))
    if expect_prefs.get_unmatched():
        st.report_fail("msg", "Did not receive: {}".format(expect_prefs.get_unmatched()))
    st.report_pass("test_case_passed")


def _matches(value, exp_value):
    '''Returns True if a value equals the expected value. None expected value matches any value.'''
    return exp_value is None or value == exp_value


class PreferenceMatcher(object):
    def __init__(self, prefs):
        self.prefs = None
        self.match = set()
        if prefs is not None:
            # Rearrange the Pref list to have exact match or longest prefix match in one iteration
            def keyFunc(x): return "~"+x.path if x.path_prefix is None else x.path_prefix
            self.prefs = sorted(prefs, key=keyFunc, reverse=True)

    def matches(self, resp):
        if self.prefs is None:
            return True
        for i, p in enumerate(self.prefs):
            if p.match(resp):
                self.match.add(i)
                return True
        return False

    def get_unmatched(self):
        if self.prefs is None:
            return []
        return [p for i, p in enumerate(self.prefs) if i not in self.match]

    def __str__(self):
        if self.prefs is None:
            return "None"
        s = ""
        for i, p in enumerate(self.prefs):
            s += "#{}: {}{}\n".format(i+1, p, (" (matched)" if i in self.match else ""))
        return s

###############################################
# TODO move to a common utils module


def pb_dict(msg):
    '''Returns a protobuf message as a JSON dictionary'''
    return MessageToDict(msg, including_default_value_fields=True, preserving_proto_field_name=True)


def as_grpc_status(s):
    if isinstance(s, StatusCode):
        return s
    if isinstance(s, int):
        for status in StatusCode.__members__.values():
            if status.value[0] == s: return status
    elif isinstance(s, str):
        s = s.upper()
    return StatusCode.__members__.get(s, StatusCode.UNKNOWN)
