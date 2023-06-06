import os
import re
import sys
import ssl
import json
import queue
import six
from datetime import datetime
from datetime import timedelta
from decimal import Decimal
try: from time import monotonic as _time
except Exception: from monotonic import monotonic as _time
import grpc
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'gnmi'))
from apis.gnmi.github.com.openconfig.gnmi.proto.gnmi import gnmi_pb2
from apis.gnmi.github.com.openconfig.gnmi.proto.gnmi import gnmi_pb2_grpc
from spytest import st
from apis.yang.utils.rest import remove_module_names_and_sort
from apis.system.gnmi import crypto_cert_key_install, verify_cert_security_profile
from apis.system.basic import is_file_in_path
from apis.yang.utils.common import get_audit_msg
from utilities import common as utils
from utilities.exceptions import XpathError

_RE_GNMI_PATH_COMPONENT = re.compile(r'''
^
(?P<pname>[^[]+)  # gNMI path name
(\[(?P<key>[a-zA-Z0-9\-]+)   # gNMI path key
=
(?P<value>.*)    # gNMI path value
\])?$
''', re.VERBOSE)


def _parse_path(p_names, target="", origin=""):
    """Parses a list of path names for path keys.
    Args:
      p_names: (list) of path elements, which may include keys.
      target: target string for PATH
      origin: origin string for PATH
    Returns:
      a gnmi_pb2.Path object representing gNMI path elements.
    Raises:
      XpathError: Unable to parse the xpath provided.
    """
    gnmi_elems = []
    for word in p_names:
        word_search = _RE_GNMI_PATH_COMPONENT.search(word)
        if not word_search:  # Invalid path specified.
            raise XpathError('xpath component parse error: %s' % word)
        if word_search.group('key') is not None:  # A path key was provided.
            tmp_key = {}
            if r'\]' in word:
                word = word.replace(r'\]', r'\\')
            for x in re.findall(r'\[([^]]*)\]', word):
                if r"\\" in x.split("=")[-1]:
                    tmp_key[x.split("=")[0]] = x.split("=")[-1].replace(r'\\', r'\]').replace('\\','')
                else:
                    tmp_key[x.split("=")[0]] = x.split("=")[-1]
            gnmi_elems.append(gnmi_pb2.PathElem(name=word_search.group(
                'pname'), key=tmp_key))
        else:
            gnmi_elems.append(gnmi_pb2.PathElem(name=word, key={}))

    return gnmi_pb2.Path(elem=gnmi_elems, target=target, origin=origin)


def _path_names(xpath):
    """Parses the xpath names.
    This takes an input string and converts it to a list of gNMI Path names. Those
    are later turned into a gNMI Path Class object for use in the Get/SetRequests.
    Args:
      xpath: (str) xpath formatted path.
    Returns:
      list of gNMI path names.
    """
    path = []
    insidebracket = False
    begin = 0
    end = 0
    xpath = xpath + '/'
    while end < len(xpath):
        if xpath[end] == "/":
            if insidebracket is False:
                if end > begin:
                    path.append(xpath[begin:end])
                end = end + 1
                begin = end
            else:
                end = end + 1
        elif xpath[end] == "[":
            if (end == 0 or xpath[end - 1] != '\\') and insidebracket is False:
                insidebracket = True
            end = end + 1
        elif xpath[end] == "]":
            if (end == 0 or xpath[end - 1] != '\\') and insidebracket is True:
                insidebracket = False
            end = end + 1
        else:
            end = end + 1
    return path


def get_gnmi_path(xpath, target="", origin=""):
    """ Converts XPATH style path to GNMI PATH with target filled
    Args: YANG style xpath, target string, origin string
    """
    return _parse_path(_path_names(xpath), target, origin)


def get_gnmi_path_prefix(prefix, path_list, target='', origin='', dut=None):
    st.log("Prefix  : '{}'".format(prefix), dut=dut)
    st.log("Target  : '{}'".format(target), dut=dut)
    st.log("Origin  : '{}'".format(origin), dut=dut)
    prefix = get_gnmi_path(prefix, target, origin)
    path_rv = []
    raw_path = []
    for path in utils.make_list(path_list):
        if isinstance(path, GnmiSubscribeOptions):
            st.log("Path    : '{}'".format(path.path), dut=dut)
            raw_path.append(path.path)
            path.set_gnmi_path(path.path)
            path_rv.append(path)
            st.log("\tSample Interval    : '{}'".format(path.sample_interval), dut=dut)
            st.log("\tSuppress Redundant : '{}'".format(path.suppress_redundant), dut=dut)
            st.log("\tHeartbeat Interval : '{}'".format(path.heartbeat_interval), dut=dut)
        else:
            st.log("Path    : '{}'".format(path), dut=dut)
            raw_path.append(path)
            path_rv.append(get_gnmi_path(path, ''))
    return prefix, path_rv, raw_path


def get_target(target=''):
    if not target:
        return st.getenv("PYTEST_CURRENT_TEST", "Random_target_name_Infra").split(" ")[0]
    else:
        return target


def is_gnmi_support(dut, report=False):
    hw_list = st.get_datastore(dut, "constants")['GNMI_UNSUPPORTED_PLATFORMS']
    crnt_hw = st.get_testbed_vars().hwsku[dut].lower()
    if crnt_hw in hw_list:
        if report:
            st.report_unsupported('msg', 'gNMI is UnSupported on "{}" platform.'.format(crnt_hw))
        return False
    return True


def get_gnmi_conn(dut, save=True, connect=True, report=True, new_conn=False, trace=False, **kwargs):
    """
    Create and return gNMI connection object.
    :param dut:
    :param save:  To save the gNMI config to DUT
    :param connect: To will get cert, create Stub and check for gNMI status.
    :param report: If connect fail - report.
    :param trace:  True|False - Traces for debug low level calls.
    :param new_conn: Return New gNMI conn object.
    :param username: User defined username.
    :param password: User defined password.
    """
    if not is_gnmi_support(dut, report):
        return
    cache_name = "gnmi"
    if kwargs.get('username') and kwargs.get('password'):
        cache_name = "gnmi_{}_{}".format(kwargs.get('username'), kwargs.get('password'))

    conn = None if new_conn else st.get_cache(cache_name, dut)

    st.debug("gNMI conn object '{}' - {}".format(cache_name, conn), dut=dut)
    if not isinstance(conn, GNMIConnection):
        conn = GNMIConnection(dut, trace, cache_name=cache_name, **kwargs)
        conn.setup(save)
        st.set_cache(cache_name, conn, dut)
    if connect and not conn.isconnected():
        if not conn.connect():
            if report:
                st.report_env_fail('msg', 'Failed to create the gNMI connection Object.')
            return
    return conn


def ensure_gnmi_config_and_cert(dut, save=False):
    if is_gnmi_support(dut, report=False):
        st.log('Ensuring gNMI Config and Cert files..', dut=dut)
        conn = GNMIConnection(dut)
        conn.setup(save)


def sleep(val, **args):
    st.wait(val)


def log_step(msg, dut=None):
    st.log(msg, dut=dut)


class gNMIError(object):
    """
    gNMI Error class
    """
    def __init__(self, path, oper, error, dut=None):
        self.path = path
        self.oper = oper
        self.error = error
        self.code = -1
        self.details = self.error
        self.dut = dut
        self._log_()

    def _log_(self):
        if isinstance(self.error, grpc.RpcError):
            self.code = self.error.code()
            self.details = self.error.details()

        st.log("gNMI {} failed: code={},  path={}".format(self.oper, self.code, self.path), dut=self.dut)
        st.log("Details : {}\n".format(self.details), dut=self.dut)

    def verify_error(self, exp_error):
        """
        Error Validation.
        Ex: gNMIError.verify_error('INVALID_ARGUMENT')
        """
        if self.code != -1 and self.code == grpc.StatusCode[exp_error]:
            return True
        elif self.code == exp_error:
            return True
        st.log("Failed to match {} with exp_error_code {}".format(self.code, exp_error), dut=self.dut)
        return False

    def verify(self, expStatusCode, expErrDetails=""):
        """
        Error Validation.
        Ex: gNMIError.verify('NOT_FOUND', exp_error_message)
        """
        if (self.code == expStatusCode or (hasattr(grpc.StatusCode, expStatusCode) and self.code == grpc.StatusCode[expStatusCode])) \
            and (expErrDetails == "" or expErrDetails in str(self.error.details())):
            return True

        st.log("Failed to match {} with exp_error_code {}".format(self.code, expStatusCode), dut=self.dut)
        return False

    def is_error(self):
        """
        gNMIError.is_error()
        :return: True for not OK status
        """
        if self.code != grpc.StatusCode.OK:
            st.log("Failed with error code - {}".format(self.code), dut=self.dut)
            return True
        return False


class PathEntry(object):
    """
    Subscription Verification API will accept the object of this class as a key for path_dict
    """
    def __init__(self, path, interval=20, iteration=1):
        self.path = path
        self.target = ''
        self.interval = interval
        self.iteration = iteration

    def set_target(self, target):
        self.target = target

    def new_value_stats(self, value):
        return ValueStats(value, exp_iterations=self.iteration, exp_interval=self.interval)


class GnmiSubscribeOptions(object):
    """
    GNMI Subscribe calls will using this to pass subscription options
    """
    def __init__(self, path, sample_interval=20, suppress_redundant=False, heartbeat_interval=None):
        self.path = path
        self.sample_interval = sample_interval
        self.suppress_redundant = suppress_redundant
        self.heartbeat_interval = heartbeat_interval

    def set_gnmi_path(self, path):
        self.path = get_gnmi_path(path, '')


class GNMIReqIter(object):
  def __init__(self, timeout=None):
    self.q = queue.Queue()
    self.timeout = timeout

  def __iter__(self):
    return self

  def put(self, item):
    self.q.put(item)

  def next(self): # Python 2
    return self.__next__()

  def __next__(self):
    return self.q.get(block=True, timeout=self.timeout)


class SubscribeRpc(object):
    def __init__(self, iterator, req_iter, target=None, encoding=None, sub_type=None, path=None, origin=None,
                 timeout=None, dut=None):
        self.iterator = iterator
        self.exp_target = target
        self.si = req_iter
        self.encoding = encoding
        self.sub_type = sub_type
        self.path = path
        self.origin = origin
        self.timeout = timeout
        self.error = None  # gNMIError object
        self.dut = dut

    def __iter__(self):
        return self.iterator

    def __next__(self):
        return next(self.iterator)

    def next(self):
        return self.__next__()

    def cancel(self):
        st.log("Cancelling gNMI RPC call.", dut=self.dut)
        self.iterator.cancel()

    def clear_initial_sync(self):
        """
        Clear the GNMI Notifications before sync_response:true is received
        """
        st.log("Clearing initial sync updates.", dut=self.dut)
        is_ok = False
        try:
            for response in self.iterator:
                st.debug("Raw notification msg:\n" + str(response))
                if response.sync_response:
                    is_ok = True
                    break
                else:
                    continue
        except grpc.RpcError as ex:
            is_ok = False
            if grpc_status(ex) == grpc.StatusCode.UNKNOWN:
                st.log("Subscription timed out..", dut=self.dut)
            else:
                st.error("Unexpected RpcError: " + str(ex), dut=self.dut)
        return is_ok

    def poll(self):
        """
        Create a gNMI Poll trigger for gNMI Poll Subscription.
        :return:
        """
        if self.si:
            st.log("Sending Poll Trigger.", dut=self.dut)
            self.si.put(gnmi_pb2.SubscribeRequest(poll=gnmi_pb2.Poll()))
        else:
            st.error("Create POLL SubscribeRequest and try again.", dut=self.dut)

    def verify(self, updates={}, deletes=[], sync=False, timeout=None, **kwargs):
        return verify_notifications(self,
                                    path_dict=updates,
                                    delete_path_list=deletes,
                                    sync_response=sync, timeout=timeout, **kwargs)

    def verify_poll(self, exp_updates={}, exp_deletes=[], iteration=1, interval=10, trigger=True, timeout=None,
                    **kwargs):
        return verify_poll_subscription_response(self, exp_updates, exp_deletes, iteration=iteration,
                                                 interval=interval, trigger=trigger, timeout=timeout, **kwargs)

    def verify_error(self, exp_error=None):
        """
        Error Validation.
        Ex: SubscribeRpc.verify_error('INVALID_ARGUMENT')
        """
        try:
            self.next()
            st.log('No grpc error observed.', dut=self.dut)
            return False
        except Exception as err:
            if exp_error:
                return gNMIError(self.path, self.sub_type, err, dut=self.dut).verify_error(exp_error)
            else:
                return gNMIError(self.path, self.sub_type, err, dut=self.dut).is_error()

    def is_error(self):
        """
        Return True for not OK status.
        """
        try:
            self.next()
            st.log('No grpc error observed.')
            return False
        except Exception as err:
            return gNMIError(self.path, self.sub_type, err, dut=self.dut).is_error()


class GNMIConnection(object):

    def __init__(self, dut, trace=False, **kwargs):

        self.dut = dut
        self.port = 8080
        self.max_msg_length = 1024 * 1024 * 32
        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
        self.cache_name = kwargs.get('cache_name', 'gnmi')
        self.default_cert = kwargs.get('default_cert', True)
        self.timeout = kwargs.get('timeout', 60)
        self.reinit()
        self.__gnmi_channel = None
        self.__gnmi_stub = None
        self.secure = True
        self.gnmi_iter_timeout = None
        self.gnmi_hostname_on_cert = "localhost"
        self.profile_name = "spytest1"
        self.gnmi_cert_preserve = bool(st.getenv("SPYTEST_PRESERVE_GNMI_CERT", "0") != "0")
        self.trace = trace
        self.state_enum = {b.value[0]: a for a, b in dict(grpc.ChannelConnectivity.__members__).items()}

        self.cert_file, self.cert_key_file = "localhost.crt", "localhost.key"
        self.rmt_cert_path = '/home/admin/gnmi_certs'
        self.docker_cert_path = "/host_home/admin/gnmi_certs"
        self.rmt_cert_file = os.path.join(self.rmt_cert_path, self.cert_file)
        self.rmt_cert_key_file = os.path.join(self.rmt_cert_path, self.cert_key_file)
        self.docker_cert_file = os.path.join(self.docker_cert_path, self.cert_file)
        self.docker_cert_key_file = os.path.join(self.docker_cert_path, self.cert_key_file)
        current_dir = os.path.dirname(os.path.realpath(__file__))
        self.local_cert_file = os.path.join(current_dir, "certs", self.cert_file)
        self.local_cert_key_file = os.path.join(current_dir, "certs", self.cert_key_file)

        if self.trace:
            self.gnmi_trace()

    def log(self, msg):
        st.log(msg, dut=self.dut)

    def audit(self, msg):
        st.audit(get_audit_msg(dut=self.dut, msg=msg))

    def debug(self, msg):
        st.debug(msg, dut=self.dut)

    def reinit(self):
        self.mgmt_addr = os.getenv("SPYTEST_REST_TEST_ADDR")
        if not self.mgmt_addr:
            self.mgmt_addr = st.get_mgmt_ip(self.dut)
        credentials = st.get_credentials(self.dut)
        self.mgmt_port = os.getenv("SPYTEST_REST_TEST_PORT", str(self.port))
        self.mgmt_port = int(self.mgmt_port)
        self.mgmt_user = os.getenv("SPYTEST_REST_TEST_USER")
        if not self.mgmt_user:
            self.mgmt_user = credentials[0]
        self.mgmt_pass = os.getenv("SPYTEST_REST_TEST_PASS")
        if not self.mgmt_pass:
            self.mgmt_pass = credentials[3] # Setting up the current password for gNMI calls

        if self.username and self.password:
            self.mgmt_user = self.username
            self.mgmt_pass  = self.password

    def gnmi_trace(self, mode=True, trace='transport_security,tsi'):
        """
        To enable low level API traces to DEBUG.
        REF : https://github.com/grpc/grpc/blob/master/doc/environment_variables.md
        :param mode:
        :param trace:
        :return:
        """
        self.log('gNMI Trace - {} '.format(mode))
        if mode:
            os.environ["GRPC_TRACE"] = trace
            os.environ["GRPC_VERBOSITY"] = "DEBUG"
        else:
            os.environ["GRPC_TRACE"] = ""
            os.environ["GRPC_VERBOSITY"] = "ERROR"

    def __cli(self, cmd, timeout=20):
        if os.getenv("SPYTEST_FILE_MODE") != "1":
            self.debug("Executing: {}".format(cmd))
            return st.config(self.dut, cmd, sudo=False)
        return ""

    def __check_telemetry_docker_status(self):
        deadline = _time() + 180
        output = ""
        while 'telemetry' not in output:
            output = self.__cli("docker ps | grep telemetry", timeout=20)
            if "telemetry" in output or st.is_dry_run():
                break
            if _time() > deadline or 'Is the docker daemon running?' in output:
                return False
            sleep(5, animate=False)
        return True

    def __check_gnmi_server_status(self):
        log_step("checking GNMI server status", self.dut)
        deadline = _time() + 180
        while True:
            path = '/openconfig-system:system/config/hostname'
            response, status = self.gnmi_get(path, timeout=self.timeout)
            self.debug("GNMI GET response: {}".format(response))
            if status == 0 or st.is_dry_run():
                break
            if _time() > deadline or st.is_dry_run():
                return False
            self.log("Rechecking GNMI server status")
            sleep(5, animate=False)
        return True

    def get_channel_state(self):
        if self.__gnmi_channel:
            val = self.__gnmi_channel._channel.check_connectivity_state(True)
            name = self.state_enum[val]
            self.debug("Channel connectivity state - {}".format(name))
            return name, val
        return None, None

    def wait_for_ready(self, timeout=30):
        if self.__gnmi_channel:
            state, _ = self.get_channel_state()
            if state != grpc.ChannelConnectivity.READY.name:
                try:
                    gnmi_pb2_grpc.grpc.channel_ready_future(self.__gnmi_channel).result(timeout=timeout)
                    return True
                except grpc.FutureTimeoutError:
                    st.error('Error connecting to server - FutureTimeoutError', dut=self.dut)
                    st.set_cache(self.cache_name, None, self.dut)
                    return False

    def restart_on_disconnect(self):
        # listen to channel events and re-connect for TRANSIENT_FAILURE
        self.__gnmi_channel.subscribe(self.connectivity_event_callback)

    def connectivity_event_callback(self, event):
        if event == grpc.ChannelConnectivity.TRANSIENT_FAILURE:
            st.error("Transient failure detected - {}; re-connecting in 5 sec".format(self), dut=self.dut)
            st.wait(5)
            self.connect()
        else:
            self.log("Channel connectivity Event - {}".format(event))

    def setup(self, save=True):
        if not self.default_cert:
            self.log("GNMI setup")
            self.debug("Setting up an environment for GNMI tests")
            if not self.secure:
                self.cert_config(config=False)
                return self
            if not self.__check_cert_config_for_gnmi():
                if not st.is_dry_run() and not self.__check_cert_file_for_gnmi():
                    st.upload_file_to_dut(self.dut, self.local_cert_file, self.rmt_cert_file)
                    st.upload_file_to_dut(self.dut, self.local_cert_key_file, self.rmt_cert_key_file)
                self.cert_config()
                if save:
                    self.__cli("sudo config save -y")
                if not self.__check_telemetry_docker_status():
                    self.log('Telemetry docker is down')
            return self

    def cert_config(self, config=True, restart=True):
        return crypto_cert_key_install(self.dut, cert_file=self.rmt_cert_file, key_file=self.rmt_cert_key_file,
                                       profile_name=self.profile_name, config=config, restart=restart)

    def cleanup(self):
        if not self.default_cert:
            self.log('Removing GNMI cert configurations')
            self.cert_config(config=False)
            self.__cli("sudo rm /tmp/localhost.key /tmp/localhost.crt {} {}".format(self.rmt_cert_file, self.rmt_cert_key_file))
            self.__cli('test -f /etc/sonic/golden_config.json && '
                              'sudo cp /etc/sonic/golden_config.json /etc/sonic/config_db.json')
            if not self.__check_telemetry_docker_status():
                st.dut_log(self.dut, 'Telemetry docker is down')

    def _get_server_cert(self):
        self.log("GNMI get server certificate...")
        deadline = _time() + 180
        cert = None
        while cert is None:
            try:
                cert = ssl.get_server_certificate((self.mgmt_addr, self.mgmt_port)).encode('utf-8')
                # st.dut_log(self.dut, cert)
            except Exception as e:
                log_step("Reattempting to get server certs for GNMI due to exception {}".format(e), self.dut)
            if cert is not None or st.is_dry_run():
                break
            if _time() > deadline:
                return cert
            sleep(3, animate=False)
        return cert

    def __gnmi_create_stub(self, cert):
        self.log("GNMI create stub...")
        if self.__gnmi_channel:
            self.__gnmi_channel.unsubscribe(self.connectivity_event_callback)
            self.__gnmi_channel.close()
        ip_port = "{}:{}".format(self.mgmt_addr, self.mgmt_port)
        options = (('grpc.ssl_target_name_override', self.gnmi_hostname_on_cert),
                   (('grpc.max_receive_message_length', self.max_msg_length)))
        if cert:
            creds = gnmi_pb2_grpc.grpc.ssl_channel_credentials(root_certificates=cert, private_key=None,
                                                               certificate_chain=None)
            self.__gnmi_channel = gnmi_pb2_grpc.grpc.secure_channel(ip_port, creds, options)
        else:
            self.__gnmi_channel = gnmi_pb2_grpc.grpc.insecure_channel(ip_port, options)
        self.__gnmi_stub = gnmi_pb2_grpc.gNMIStub(self.__gnmi_channel)

    def gnmi_capabilities(self):
        """
        Create a gNMI Capabilities.
        """
        self.wait_for_ready()
        return self.__gnmi_stub.Capabilities(gnmi_pb2.CapabilityRequest())

    def gnmi_get(self, paths, target=None, encoding='JSON_IETF', origin='', filter_type=None, **kwargs):
        """Create a gNMI GetRequest.
           Args:
               paths: gNMI Path
               target: target string for PATH
               encoding: gNMI encoding value; one of JSON, BYTES, PROTO, ASCII, JSON_IETF
               origin: origin string for PATH
               filter_type: gNMI content filter type; one of CONFIG, STATE, OPERATIONAL
           Returns:
               tuple (data, status)
               data = dict with path as key and value is gnmi_pb2.Update object w.r.t path.
               status = 0 - for RPC with OK status, -1 for RPC with non-OK status
        """
        self.audit("GNMI GET Request.")
        paths = utils.make_list(paths)
        for p in paths:
            self.audit("Path   : {}".format(p))
        self.log("Target : {}".format(get_target(target)))
        self.log("Origin : {}, Filter Type: {}".format(origin, filter_type))
        gnmi_paths = [get_gnmi_path(p, get_target(target), origin) for p in paths]

        timeout = kwargs.get('timeout', 60) or self.gnmi_iter_timeout

        self.wait_for_ready()

        try:
            gnmi_get_response = self.__gnmi_stub.Get(
                gnmi_pb2.GetRequest(path=gnmi_paths, encoding=encoding, type=filter_type),
                metadata=[('username', self.mgmt_user),
                          ('password', self.mgmt_pass)], timeout=timeout)
            response = {}
            if gnmi_get_response:
                if gnmi_get_response.notification:
                    for iterator in gnmi_get_response.notification:
                        for update in iterator.update:
                            xpath = gnmi_to_xpath(update.path)
                            # self.log("Received Update Notification: {} : {}".format(xpath, str(update.val).strip()))
                            response[xpath] = update
            return response, 0

        except Exception as err:
            return gNMIError(paths, 'Get', err, dut=self.dut), -1


    def gnmi_set(self, delete=[], replace=[], update=[], encoding='JSON_IETF', origin='', **kwargs):
        """
        Changing the configuration on the destination network elements.
        Could provide a single attribute or multiple attributes.

        delete:
          - list of paths with the resources to delete. The format is the same as for get() request

        replace:
          - list of tuples where the first entry path provided as a string, and the second entry
            is a dictionary with the configuration to be configured

        update:
          - list of tuples where the first entry path provided as a string, and the second entry
            is a dictionary with the configuration to be configured

        The encoding argument may have the following values per gNMI specification:
          - JSON
          - BYTES
          - PROTO
          - ASCII
          - JSON_IETF

        origin: origin string for PATH
        """
        del_protobuf_paths = []
        replace_msg = []
        update_msg = []
        all_paths = []
        ops_typ = gnmi_pb2.UpdateResult.Operation  #pylint: disable=no-member
        ops_v2k = {v: k for k, v in ops_typ.items()}
        rv_fail = (None, -1)

        if not validate_enum(encoding, gnmi_pb2.Encoding):
            return

        timeout = kwargs.get('timeout', 60) or self.gnmi_iter_timeout

        self.wait_for_ready()

        if delete:
            self.audit("GNMI SET Delete: ")
            oper_type = 'Delete'
            if isinstance(delete, list):
                all_paths += delete
                try:
                    for pe in delete:
                        self.audit("Path: {}".format(pe))
                        del_protobuf_paths.append(get_gnmi_path(pe, get_target(), origin=origin))

                except Exception:
                    st.error('Conversion of gNMI paths to the Protobuf format failed', dut=self.dut)
                    return rv_fail
            else:
                st.error('The provided input for Set message (delete operation) is not list.', dut=self.dut)
                return rv_fail

        if replace:
            self.audit("GNMI SET Replace: ")
            oper_type = 'Replace'
            if isinstance(replace, list):
                all_paths += replace
                for ue in replace:
                    if isinstance(ue, tuple):
                        u_path = get_gnmi_path(ue[0], get_target(), origin=origin)
                        u_val = ue[1]
                        self.audit("Path: {}".format(ue[0]))
                        self.audit("Value: {}".format(u_val))
                        replace_msg.append(gnmi_pb2.Update(path=u_path, val=_get_typedvalue(u_val, encoding)))
                    else:
                        st.error('The input element for Update message must be tuple, got {}.'.format(ue), dut=self.dut)
                        return rv_fail
            else:
                st.error('The provided input for Set message (replace operation) is not list.')
                return rv_fail

        if update:
            self.audit("GNMI SET Update: ")
            oper_type = 'Update'
            if isinstance(update, list):
                all_paths += update
                for ue in update:
                    if isinstance(ue, tuple):
                        u_path = get_gnmi_path(ue[0], get_target(), origin=origin)
                        u_val = ue[1]
                        self.audit("Path: {}".format(ue[0]))
                        self.audit("Value: {}".format(u_val))
                        update_msg.append(gnmi_pb2.Update(path=u_path, val=_get_typedvalue(u_val, encoding)))
                    else:
                        st.error('The input element for Update message must be tuple, got {}.'.format(ue))
                        return rv_fail
            else:
                st.error('The provided input for Set message (update operation) is not list.')
                return rv_fail

        self.log("Encoding : {}".format(encoding))
        self.log("Origin   : {}".format(origin))

        try:
            gnmi_message_request = gnmi_pb2.SetRequest(delete=del_protobuf_paths, update=update_msg,
                                                       replace=replace_msg)
            gnmi_message_response = self.__gnmi_stub.Set(gnmi_message_request,
                                                         metadata=[('username', self.mgmt_user),
                                                                   ('password', self.mgmt_pass)],
                                                         timeout=timeout)

            if gnmi_message_response:
                response = {}

                if gnmi_message_response.response:
                    response.update({'response': []})

                    for response_entry in gnmi_message_response.response:
                        response_container = {}

                        # Adding path
                        if response_entry.path and response_entry.path.elem:
                            response_container.update({'path': gnmi_to_xpath(response_entry.path)})
                        else:
                            response_container.update({'path': None})

                        # Adding operation
                        if response_entry.op in ops_v2k:
                            response_container.update({'op': ops_v2k[response_entry.op]})
                        else:
                            response_container.update({'op': 'UNDEFINED'})

                        response['response'].append(response_container)

                self.debug(response)
                return response, 0

            else:
                st.error('Failed parsing the SetResponse.', dut=self.dut)
                return rv_fail

        except Exception as err:
            return gNMIError(all_paths, oper_type, err, dut=self.dut), -1


    def gnmi_update(self, update=[], encoding='JSON_IETF', origin='', **kwargs):
        """
        Changing the configuration on the destination network elements.
        Could provide a single attribute or multiple attributes.

        update:
          - list of tuples where the first entry path provided as a string, and the second entry
            is a dictionary with the configuration to be configured

        The encoding argument may have the following values per gNMI specification:
          - JSON
          - BYTES
          - PROTO
          - ASCII
          - JSON_IETF

        origin: origin string for PATH
        """
        return self.gnmi_set(update=update, encoding=encoding, origin=origin, **kwargs)

    def gnmi_replace(self, replace=[], encoding='JSON_IETF', origin='', **kwargs):
        """
        Changing the configuration on the destination network elements.
        Could provide a single attribute or multiple attributes.

        replace:
          - list of tuples where the first entry path provided as a string, and the second entry
            is a dictionary with the configuration to be configured

        The encoding argument may have the following values per gNMI specification:
          - JSON
          - BYTES
          - PROTO
          - ASCII
          - JSON_IETF

        origin: origin string for PATH
        """
        return self.gnmi_set(replace=replace, encoding=encoding, origin=origin, **kwargs)

    def gnmi_delete(self, delete=[], encoding='JSON_IETF', origin='', **kwargs):
        """
        Changing the configuration on the destination network elements.
        Could provide a single attribute or multiple attributes.

        delete:
          - list of paths with the resources to delete. The format is the same as for get() request

        The encoding argument may have the following values per gNMI specification:
          - JSON
          - BYTES
          - PROTO
          - ASCII
          - JSON_IETF

        origin: origin string for PATH
        """
        return self.gnmi_set(delete=delete, encoding=encoding, origin=origin, **kwargs)

    def gnmi_subscribe_onchange(self, path_list, timeout=None, encoding="JSON", updates_only=False,
                                target=None, prefix='/', origin=''):
        """Create a gNMI On-Change Subscribe request
           Args:
               path_list:
               timeout:
               encoding: gNMI encoding value; one of JSON, BYTES, PROTO, ASCII, JSON_IETF
               updates_only: Bool value for SubscriptionList.updates_only; default False.
               target: Prefix target str; auto assigns a default value.
               prefix: gNMI Path prefix
               origin: origin string for PATH
           Returns:
               GNMI Request iterator
        """
        self.log("GNMI ON_CHANGE Subscribe Request.")
        timeout = timeout or self.gnmi_iter_timeout
        return self.__gnmi_subscribe(path_list, timeout, encoding, "ON_CHANGE",
                                     updates_only=updates_only, target=target, prefix=prefix, origin=origin)

    def gnmi_subscribe_sample(self, path_list, timeout=None, encoding="JSON", updates_only=False,
                              sample_interval=20, suppress_redundant=False, heartbeat_interval=None,
                              target=None, prefix='/', origin=''):
        """Create a gNMI Sample Subscribe request
           Args:
               path_list: gNMI Path
               timeout:
               encoding: gNMI encoding value; one of JSON, BYTES, PROTO, ASCII, JSON_IETF
               updates_only: Bool value for SubscriptionList.updates_only; default False.
               sample_interval:
               suppress_redundant:
               heartbeat_interval:
               target: Prefix target str; auto assigns a default value.
               prefix: gNMI Path prefix
               origin: origin string for PATH
           Returns:
               GNMI Request iterator
        """
        self.log("GNMI SAMPLE Subscribe Request.")
        timeout = timeout or self.gnmi_iter_timeout
        path_li = []
        for p in utils.make_list(path_list):
            if utils.is_unicode_string(p):
                path_li.append(GnmiSubscribeOptions(p, sample_interval=sample_interval,
                                                    suppress_redundant=suppress_redundant,
                                                    heartbeat_interval=heartbeat_interval))
            elif isinstance(p, GnmiSubscribeOptions):
                path_li.append(p)
        return self.__gnmi_subscribe(path_li, timeout, encoding, "SAMPLE",
                                     updates_only=updates_only, target=target, prefix=prefix, origin=origin)

    def gnmi_subscribe_target_defined(self, path_list, timeout=None, encoding="JSON", updates_only=False,
                                      sample_interval=None, suppress_redundant=False, heartbeat_interval=None,
                                      target=None, prefix='/', origin=''):
        """Create a gNMI Target Defined Subscribe request
           Args:
               path_list: gNMI Path
               timeout:
               encoding: gNMI encoding value; one of JSON, BYTES, PROTO, ASCII, JSON_IETF
               updates_only: Bool value for SubscriptionList.updates_only; default False.
               sample_interval:
               suppress_redundant:
               heartbeat_interval:
               target: Prefix target str; auto assigns a default value.
               prefix: gNMI Path prefix
               origin: origin string for PATH
           Returns:
               GNMI Request iterator
        """
        self.log("GNMI TARGET_DEFINED Subscribe Request.")
        timeout = timeout or self.gnmi_iter_timeout
        if sample_interval:
            path_li = []
            for p in utils.make_list(path_list):
                if utils.is_unicode_string(p):
                    path_li.append(GnmiSubscribeOptions(p, sample_interval=sample_interval,
                                                        suppress_redundant=suppress_redundant,
                                                        heartbeat_interval=heartbeat_interval))
                elif isinstance(p, GnmiSubscribeOptions):
                    path_li.append(p)
        else:
            path_li = path_list
        return self.__gnmi_subscribe(path_li, timeout, encoding, "TARGET_DEFINED",
                                     updates_only=updates_only, target=target, prefix=prefix, origin=origin)

    def gnmi_subscribe_poll(self, path_list, timeout=None, encoding="JSON", updates_only=False,
                            target=None, prefix='/', origin=''):
        """Create a gNMI Poll Subscribe request
           Args:
               path_list: gNMI Path
               timeout:
               encoding: gNMI encoding value; one of JSON, BYTES, PROTO, ASCII, JSON_IETF
               updates_only: Bool value for SubscriptionList.updates_only; default False.
               target: Prefix target str; auto assigns a default value.
               prefix: gNMI Path prefix
               origin: origin string for PATH
           Returns:
               GNMI Request iterator
        """
        self.log("GNMI POLL Subscribe Request.")
        timeout = timeout or self.gnmi_iter_timeout
        return self.__gnmi_subscribe(path_list, timeout, encoding, query_type="POLL",
                                     updates_only=updates_only, target=target, prefix=prefix, origin=origin)

    def gnmi_subscribe_once(self, path_list, timeout=None, encoding="JSON", updates_only=False,
                            target=None, prefix='/', origin=''):
        """Create a gNMI Once Subscribe request
           Args:
               path_list: gNMI Path
               timeout:
               encoding: gNMI encoding value; one of JSON, BYTES, PROTO, ASCII, JSON_IETF
               updates_only: Bool value for SubscriptionList.updates_only; default False.
               target: Prefix target str; auto assigns a default value.
               prefix: gNMI Path prefix
               origin: origin string for PATH
           Returns:
               GNMI Request iterator
        """
        self.log("GNMI ONCE Subscribe Request.")
        timeout = timeout or self.gnmi_iter_timeout
        return self.__gnmi_subscribe(path_list, timeout, encoding, query_type="ONCE",
                                     updates_only=updates_only, target=target, prefix=prefix, origin=origin)

    def __gnmi_subscribe(self, path_list, timeout=None, encoding="JSON", mode="ON_CHANGE",
                         query_type="STREAM", updates_only=False,
                         target=None, prefix='/', origin=''):
        """Create a gNMI On-Change Subscribe request
           Args:
               path_list: gNMI Path
               prefix: gNMI Path prefix
               encoding: gNMI encoding value; one of JSON, BYTES, PROTO, ASCII, JSON_IETF
               mode: SAMPLE, ON_CHANGE, TARGET_DEFINED
               query_type: STREAM, POLL, ONCE
               updates_only: Bool value for SubscriptionList.updates_only; default False.
               target: Prefix target str; auto assigns a default value.
               prefix: gNMI Path prefix
               origin: origin string for PATH
           Returns:
               GNMI Request iterator
        """
        sub_type = "{} {}".format(query_type, mode)
        target = get_target(target)
        prefix, path_list, raw_path = get_gnmi_path_prefix(prefix, path_list, target, origin, self.dut)
        timeout = timeout or self.gnmi_iter_timeout
        self.log("Encoding : {}".format(encoding))
        self.log("Timeout : {}".format(timeout))

        if not validate_enum(encoding, gnmi_pb2.Encoding):
            return

        subs = []
        for path_entry in path_list:
            opt_dict = dict()
            opt_dict["mode"] = mode
            if isinstance(path_entry, gnmi_pb2.Path):
                opt_dict["path"] = path_entry
            elif isinstance(path_entry, GnmiSubscribeOptions):
                opt_dict["path"] = path_entry.path
                if path_entry.sample_interval is not None:
                    opt_dict["sample_interval"] = path_entry.sample_interval * 1000000000
                if path_entry.suppress_redundant:
                    opt_dict["suppress_redundant"] = path_entry.suppress_redundant
                if path_entry.heartbeat_interval is not None:
                    opt_dict["heartbeat_interval"] = path_entry.heartbeat_interval * 1000000000
            else:
                st.error('Path entry for subscription can either be GNMI Path or a GnmiSubscribeOptions object')
            sub = gnmi_pb2.Subscription(**opt_dict)
            subs.append(sub)
        sublist = gnmi_pb2.SubscriptionList(prefix=prefix, mode=query_type,
                                            updates_only=updates_only,
                                            encoding=encoding, subscription=subs)
        subreq = gnmi_pb2.SubscribeRequest(subscribe=sublist)

        si = GNMIReqIter(timeout)
        si.put(subreq)

        self.wait_for_ready()

        try:
            metadata = [('username', self.mgmt_user), ('password', self.mgmt_pass)]
            iterator = self.__gnmi_stub.Subscribe(si, metadata=metadata)
            return SubscribeRpc(iterator, si, target=target, encoding=encoding, sub_type=sub_type, path=raw_path,
                                origin=origin, timeout=timeout, dut=self.dut)

        except Exception as err:
            return gNMIError(raw_path, sub_type, err, dut=self.dut)

    def isconnected(self):
        return bool(self.__gnmi_stub)

    def connect(self):
        st.dut_log(self.dut, "GNMI connect...")
        self.reinit()
        st.debug("Using cred - {}/{}".format(self.mgmt_user, self.mgmt_pass), self.dut)
        if self.mgmt_pass is None:
            st.error('Auth-Err observed on Infra Init, Please check the device connectivity.', dut=self.dut)
            return False
        if self.secure:
            log_step('Getting server cert for GNMI', self.dut)
            cert = self._get_server_cert()
            if cert is not None:
                self.__gnmi_create_stub(cert)
            else:
                st.error('Unable to get server Cert for GNMI, GNMI Stub is not initialized', dut=self.dut)
                return False
        else:
            self.__gnmi_create_stub(None)
        if not self.__check_gnmi_server_status():
            st.error('Telemetry server is not in working state, GNMI cases may fail', dut=self.dut)
            return False
        self.restart_on_disconnect()
        return True

    def disconnect(self):
        st.dut_log(self.dut, "GNMI disconnect...")
        if self.__gnmi_channel:
            self.__gnmi_channel.close()
            self.__gnmi_channel = None
            self.__gnmi_stub = None
            st.set_cache("gnmi", None, self.dut)
        if not self.gnmi_cert_preserve:
            self.cleanup()

    def __check_cert_config_for_gnmi(self):
        """
        Checking for Gnmi Config.
        """
        return verify_cert_security_profile(self.dut, cert=self.cert_file, profile_name=self.profile_name,
                                            telemetry_profile_name=self.profile_name)

    def __check_cert_file_for_gnmi(self):
        """
        Check for cert and key files in device.
        """
        return is_file_in_path(self.dut, self.rmt_cert_path, [self.cert_file, self.cert_key_file],
                               search_keyword='localhost')


def _create_json_from_gnmi_path(path, payload=None):
    """ Creates IETF JSON from GNMI PATH and merges payload
    Args: GNMI PATH Object, Payload in JSON format
    """
    result = {}
    orig_result = result
    for index, elem in enumerate(path.elem):
        key_dict = dict(elem.key)
        if len(key_dict) > 0:
            if index + 1 == len(path.elem) and payload:
                # TODO result[elem.name] = [{**key_dict, **payload[elem.name]}]
                key_dict.update(payload[elem.name])
                result[elem.name] = [key_dict]
            else:
                result[elem.name] = [key_dict]
            result = result[elem.name][0]
        else:
            if index + 1 == len(path.elem) and payload:
                if elem.name in payload:
                    result[elem.name] = payload[elem.name]
                elif utils.is_unicode_string(payload):
                    result[elem.name] = payload
                else:
                    st.error("{} not present in payload".format(elem.name))
                    return {}
            else:
                result[elem.name] = {}
            result = result[elem.name]
    return orig_result


def _create_json_from_xpath(path, payload=None):
    """ Creates IETF JSON from XPATH and merges payload
    Args: XPATH String, Payload in JSON format
    """
    result = {}
    orig_result = result
    path_data = list(filter(None, path.split('/')))
    for index, entry in enumerate(path_data):
        if '[' not in entry:
            if index + 1 == len(path_data) and payload:
                result[entry] = payload
            else:
                result[entry] = {}
            result = result[entry]
        else:
            entries = entry.split('[')
            for word in entries:
                if '=' not in word:
                    if index + 1 == len(path_data) and payload:
                        result[word] = [payload]
                    else:
                        result[word] = [{}]
                    result = result[word][0]
                else:
                    key_name = word.split('=')[0]
                    key_val = word.split('=')[1][:-1]
                    try:
                        key_val = int(key_val)
                    except Exception:
                        try:
                            key_val = float(key_val)
                        except Exception:
                            pass
                    result[key_name] = key_val
    return orig_result


def flush_pre_sync_reponses(iterator):
    """
    Flushes the GNMI Notifications before sync_response:true is received
    Args:
           iterator: GNMI Subscription response iterator
    Returns:
           True when success else False
    """
    is_ok = False
    try:
        for response in iterator:
            if response.sync_response:
                is_ok = True
                break
            else:
                continue
    except Exception:
        log_step("Subscription timed out")  # not error
        is_ok = False
    return is_ok


def validate_notification_interval(sample_time_iter_map):
    is_ok = True
    for notif_path in sample_time_iter_map:
        expected_interval = timedelta(seconds=sample_time_iter_map[notif_path][0]).seconds
        expected_iterations = sample_time_iter_map[notif_path][1]
        notification_ts = sample_time_iter_map[notif_path][2]
        received_iterations = len(notification_ts)
        if len(notification_ts) != expected_iterations:
            is_ok = False
            st.error("Expected number of iterations for path {} is {} but received is {}".format(notif_path, expected_iterations, received_iterations))
        if received_iterations > 1:
            index = 0
            while index+1 < received_iterations:
                current_ts = notification_ts[index]
                next_ts = notification_ts[index+1]
                index = index + 1
                delta = next_ts - current_ts
                new_delta = delta.seconds
                if abs(new_delta - expected_interval) > 3:
                    is_ok = False
                    st.error("Expected interval between notifications for path {} is {} but received interval is {}".format(notif_path, expected_interval, new_delta))

    return is_ok


def _extract_path_entries(path_entry, iter_map, mode="onchange"):
    if isinstance(path_entry, tuple):
        path = path_entry[0]
        target = path_entry[1]
        interval = 20
        iteration = 1
        if len(path_entry) > 2:
            interval = path_entry[2]
        if len(path_entry) > 3:
            iteration = path_entry[3]
    elif isinstance(path_entry, PathEntry):
        path = path_entry.path
        target = path_entry.target
        if mode == "sample":
            interval = path_entry.interval
            iteration = path_entry.iteration
    else:
        st.error('Path Entry can either be a tuple or an instance of PathEntry class')

    gnmi_path = str(get_gnmi_path(path, target))
    if mode == "sample":
        if gnmi_path not in iter_map:
            iter_map[gnmi_path] = (interval, iteration, [])
    return path, target, gnmi_path


def verify_subscribe_response(rpc_context, path_dict, delete_path_list=None, sync_response=False, timeout=None,
                              **kwargs):
    """
    Verifies the subscription Response
    Validates https://github.com/openconfig/gnmi/blob/d2b4e6a45802a75b3571a627519cae85a197fdda/proto/gnmi/gnmi.proto#L85
    Args:
           rpc_context: GNMI Subscription response rpc
           path_dict: A dict whose key is a tuple whose format is (xpath, prefix(gnmi)) and value is a JSON/list
           of JSON (expected response for the path)
           delete_path_list: A list which contains delete paths
           sync_response: If true breaks iterator listener if sync_response:true is received
           match_subset: True to match subset of Updates.
    Returns:
           True when validation passes else False
    """
    return verify_notifications(rpc_context, path_dict, delete_path_list, sync_response, timeout=timeout, **kwargs)


def verify_poll_subscription_response(rpc_context, path_dict, delete_path_list=None, iteration=1, interval=10,
                                      trigger=True, timeout=None, **kwargs):
    """
    :param rpc_context: GNMI Subscription response rpc
    :param path_dict: A dict whose key is a tuple whose format is (xpath, prefix(gnmi)) and value is a JSON/list
           of JSON (expected response for the path)
    :param delete_path_list: A list which contains delete paths
    :param iteration: poll iteration (Default:1)
    :param interval: Poll interval (Default:10s)
    :param trigger: True | False, for initial notification Trigger = False (Default: True)
    :param timeout: For call timeout
    :param match_subset: True to match subset of Updates.
    :return:
    """
    is_ok = True
    for i in range(1, iteration+1):
        if trigger:
            st.log("Poll Iteration - {}".format(i))
            rpc_context.poll()
            if not verify_notifications(rpc_context, path_dict, delete_path_list, True, timeout=timeout, **kwargs):
                return False
            if i != iteration:
                st.wait(interval, " Poll Interval ")
        else:
            if not verify_notifications(rpc_context, path_dict, delete_path_list, True, timeout=timeout, **kwargs):
                return False
    return is_ok


def get_gnmi_val(raw):
    out = extract_gnmi_val(raw)
    if isinstance(out, (list, dict)):
        return out
    return str(out)


def extract_gnmi_val(raw):
    val = None
    if raw.HasField("any_val"):
        val = raw.any_val
    elif raw.HasField("ascii_val"):
        val = raw.ascii_val
    elif raw.HasField("bool_val"):
        val = raw.bool_val
    elif raw.HasField("bytes_val"):
        val = raw.bytes_val
    elif raw.HasField("decimal_val"):
        val = raw.decimal_val
        val = Decimal(str(val.digits / 10**val.precision))
    elif raw.HasField("float_val"):
        val = raw.float_val
    elif raw.HasField("int_val"):
        val = raw.int_val
    elif raw.HasField("json_ietf_val"):
        val = json.loads(raw.json_ietf_val)
    elif raw.HasField("json_val"):
        val = json.loads(raw.json_val)
    elif raw.HasField("leaflist_val"):
        val = []
        for elem in raw.leaflist_val.element:
            val.append(extract_gnmi_val(elem))
    elif raw.HasField("proto_bytes"):
        val = raw.proto_bytes
    elif raw.HasField("string_val"):
        val = raw.string_val
    elif raw.HasField("uint_val"):
        val = raw.uint_val
    else:
        raise ValueError("Unhandled typed value %s" % raw)
    return val


def validate_enum(v, e_type):
    if v in e_type.values() + e_type.keys():
        return True
    else:
        st.error('Invalid value {} for enum {}, Should be one of {}'.
                 format(v, e_type.DESCRIPTOR.full_name, e_type.values() + e_type.keys()))
        return False


def gnmi_to_xpath(p):
    path_str = ''
    for pe in p.elem:
        path_str += '/' + pe.name + _format_xpath_keys(pe.key)
    return path_str


def _format_xpath_keys(keys):
    key_comps = ""
    for k in sorted(keys):
        v = str(keys[k])
        v = v.replace('\\', '\\\\')  # Escape \ and ] inside the key value
        v = v.replace(']', '\\]')
        key_comps += '[{}={}]'.format(k, v)
    return key_comps


def _get_typedvalue(json_value, encoding):
    """Get the gNMI val for path definition.

    Args:
    json_value: (str) JSON_IETF .

    Returns:
    gnmi_pb2.TypedValue()
    """

    encoding_to_typedvalue = {'JSON': 'json_val', 'BYTES': 'bytes_val', 'PROTO': 'proto_bytes', 'ASCII': 'ascii_val',
                              'JSON_IETF': 'json_ietf_val'}

    val = gnmi_pb2.TypedValue()
    if six.PY2:
        corrected_val = _format_type(json.dumps(json_value).encode('utf-8'))
    else:
        corrected_val = _format_type(json.dumps(json_value)).encode('utf-8')
    setattr(val, encoding_to_typedvalue.get(encoding), corrected_val)
    return val


def _format_type(val):
    """Helper to determine the Python type of the provided value from CLI.

    Args:
      val: (str) Value providing from CLI.

    Returns:
      json_value: The provided input corrected into proper Python Type.
    """
    if (val.startswith('-') and val[1:].isdigit()) or (val.isdigit()):
        return int(val)
    if (val.startswith('-') and val[1].isdigit()) or (val[0].isdigit()):
        return float(val)
    if val.capitalize() == 'True':
        return True
    if val.capitalize() == 'False':
        return False

    # The value is a string.
    return val


def grpc_status(ex):
    if isinstance(ex, grpc.RpcError):
        #pylint: disable=no-member
        return ex.code()
    return grpc.StatusCode.UNKNOWN


def verify_notifications(rpc_context, path_dict={}, delete_path_list=[], sync_response=False, timeout=None, **kwargs):
    """verify_notifications reads notification messages from a Subscribe rpc context and validates
    them against specified expected values. Returns True if the validation was successful.
    Function blocks till expected values are received or till rpc times out (as indicated in
    conn.gnmi_subscribe_xxxx function).

    This API works with scalar encoded updates as well as legacy json encoded updates.
    It converts both expected update values and actual values into a scalar map and compares
    them. It can be used to verify notification messages on any type of subscription.

    Args:
        rpc_context:
            Subscribe rpc context; used to iterate over responses.
        path_dict:
            Dict containing expected update values. The key can be a gnmi xpath string
            or a PathEntry object. Dict value should be a scalar value or a json object.
            If the key is a PathEntry object, then its interval and iterations property
            is applied to every leaf value in the json.
        delete_path_list:
            List of expected delete xpath strings.
        sync_response:
            Indicate if API should wait for a sync_response. Default False.
        timeout:
            For call timeout
        match_subset:
            True to match subset of Updates.
        remove_module:
            True to match Updates by removing path module names.
    Returns:
        True if validation was successful.
        Can raise ValueError if path_dict or delete_path_list contains invalid values.
    """
    pid = None
    is_ok = True
    is_val_ok = True
    match_subset = kwargs.get('match_subset', False)
    rm_module = kwargs.get('remove_module', False)
    if rm_module:
        st.log("Validating notification by removing the Module names in path as 'remove_module' = {}".format(rm_module))
    # Match criteria
    update_stats = Scalars(rm_module)
    target = rpc_context.exp_target
    dut = rpc_context.dut
    timeout = timeout if timeout else rpc_context.timeout
    # Exit criteria
    sync_received = False
    pending_updates = []
    pending_deletes = []

    # Prepare a {leaf_path, ValueStats} map using from path_dict.
    # Will be used to match & track update values.
    for p in path_dict:
        value = path_dict[p]
        if isinstance(p, PathEntry):
            update_stats.put(p.path, value, value_xfmr=p.new_value_stats)
        elif isinstance(p, tuple):
            p = PathEntry(*p)
            update_stats.put(p.path, value, value_xfmr=p.new_value_stats)
        else:
            update_stats.put(p, value, value_xfmr=_default_value_stats)

    # Pending update & delete paths are used for loop control.
    pending_updates = [p for p in update_stats]
    pending_deletes = [p for p in delete_path_list]

    if pending_updates:
        st.log("Expected updates:\n" + str(update_stats), dut=dut)
    if pending_deletes:
        st.log("Expected deletes:\n" + "\n".join(pending_deletes), dut=dut)
    st.log("Expected sync_response: " + str(sync_response), dut=dut)

    # Checking for errors in rpc_context .
    if isinstance(rpc_context, gNMIError):
        return False

    try:
        if timeout:
            pid = st.profiling_start('Timeout', timeout, skip_report=True)

        for response in rpc_context:
            # TODO use timestamp from the update message itself??
            received_ts = datetime.now()

            st.debug("Raw notification msg:\n" + str(response), dut=dut)

            # Always break the loop upon sync message
            if response.sync_response:
                st.log("sync_response:true received", dut=dut)
                sync_received = True
                break

            # Prefix target validation
            msg = response.update
            if (msg.delete or msg.update) and msg.prefix.target != target:
                is_ok = False
                st.error("Invalid target: expected '{}', received '{}'".format(
                    target, msg.prefix.target), dut=dut)
                break

            # Loop thru deletes and check if they are in pending_deletes list.
            for delete in msg.delete:
                path = gnmi_to_xpath(msg.prefix) + gnmi_to_xpath(delete)
                st.log("Received Delete Notification: {}".format(path), dut=dut)

                if path in pending_deletes:
                    pending_deletes.remove(path)
                else:
                    st.error("Unexpected delete: " + path, dut=dut)
                    is_ok = False

            # Loop thru updates and prepare a scalar value map. Converts json encoded
            # updates also into scalars here.
            update_values = Scalars(rm_module)
            for update in msg.update:
                path = gnmi_to_xpath(msg.prefix) + gnmi_to_xpath(update.path)
                if rm_module:
                    path = remove_module_name_from_xpath(path)
                st.log("Received Update Notification: {} : {}".format(path, str(update.val).strip()), dut=dut)
                update_values.put(path, extract_gnmi_val(update.val))

            # Match the received scalar update values against update_stats dict
            for path, value in update_values.items():
                stat = update_stats.get(path)
                if stat is None:
                    st.error("Unexpected update: {}".format(path), dut=dut)
                    is_ok = False
                    continue

                # Value comparing
                is_val_ok = stat.compare_value(path, value)
                is_ok &= is_val_ok

                # Record the timestamp and remove the path from pending_updates if
                # expected number of updates received. Do not care if values matched.
                # Otherwise we may be waiting forever when values do not match.
                stat.recv_timestamps.append(received_ts)
                if stat.is_done() and path in pending_updates:
                    pending_updates.remove(path)

            # Stop iteration if we received all expected updates and deletes. But sync
            # verification will continue till a sync message is received.
            if not sync_response and len(pending_deletes) == 0 and len(pending_updates) == 0:
                break

    except grpc.RpcError as ex:
        if grpc_status(ex) == grpc.StatusCode.UNKNOWN:
            #TODO: can we check if GnmiReqIter really timed out??
            st.log("Subscription timed out..", dut=dut)
        else:
            st.error("Unexpected RpcError: " + str(ex), dut=dut)
            rpc_context.error = gNMIError(rpc_context.path, rpc_context.sub_type, ex, dut=dut)
            is_ok = False

    except Exception as ex:
        st.error("gNMI notification verification taking unexpectedly long time - {}".format(ex), dut=dut)
        is_ok = False

    finally:
        if timeout and pid is not None:
            st.profiling_stop(pid)

    if sync_response != sync_received:
        is_ok = False
        if sync_received:
            st.error("Received unexpected sync message", dut=dut)
        else:
            st.error("No sync message received", dut=dut)

    if len(pending_deletes) > 0:
        is_ok = False
        for path in pending_deletes:
            st.error("Missing delete: {}".format(path), dut=dut)

    for path, stat in update_stats.items():
        is_ok &= stat.validate(path)

    if match_subset:
        st.log("Match Subset is Enabled.")
        if len(pending_updates) == 0 and is_val_ok:
            is_ok = True

    st.log("verify_notifications: is_ok = {}".format(is_ok), dut=dut)
    return is_ok


def _default_value_stats(value):
    return ValueStats(exp_value=value)


class ValueStats:
    """ValueStats holds expected and received stats for one scalar value."""

    def __init__(self, exp_value, exp_iterations=1, exp_interval=None):
        self.exp_value = exp_value
        self.exp_iterations = exp_iterations
        self.exp_interval = exp_interval
        self.recv_timestamps = []

    def __str__(self):
        return "(value={}, iters={}, interval={})".format(
            self.exp_value, self.exp_iterations, self.exp_interval)

    def is_done(self):
        exp_count = (1 if self.exp_iterations is None else self.exp_iterations)
        return exp_count == len(self.recv_timestamps)

    def compare_value(self, path, value):
        # Handling "leaflist_val" payload
        if isinstance(self.exp_value, list):
            for e in self.exp_value:
                if e not in value:
                    st.error("Value mismatch for {}: expected={}, received={}".format(
                        path, self.exp_value, value))
                    return False
        elif value != self.exp_value:
            if value != type(value)(self.exp_value):
                st.error("Value mismatch for {}: expected={}, received={}".format(
                    path, self.exp_value, value))
                return False
        return True

    def validate(self, path):
        recv_count = len(self.recv_timestamps)
        # There should be at least one update
        if recv_count == 0:
            st.error("Missing update: {}".format(path))
            return False
        # Number of updates should match the expected count, if specified
        if self.exp_iterations and self.exp_iterations != recv_count:
            st.error("Received {} updates for path {}. Expecting {}".format(
                recv_count, path, self.exp_iterations))
            return False
        # Interval between updates should not deviate more than 3secs from
        # the expected interval, if specified
        if self.exp_interval and recv_count > 1:
            deviation = abs(self.max_interval() - self.exp_interval)
            if deviation > 3:
                msg = "Expected interval between notifications for path {} is {}s;"
                msg = msg + "but received interval is {}s"
                st.error(msg.format(path, self.exp_interval, self.max_interval()))
                return False
        return True

    def max_interval(self):
        maxi = 0
        for i in range(1, len(self.recv_timestamps)):
            interval = self.recv_timestamps[i] - self.recv_timestamps[i-1]
            maxi = max(interval.seconds, maxi)
        return maxi


class Scalars(dict):
    """Scalars is a dict of {leaf_path, scalar_value} pairs. Scalar value can be
    an int, str, bool or array of these. Normal dict iteration and read and write
    operations are allowed. But it is strongly advised to use the put() function
    for adding values to this map. The put() function automatically expands the
    json values into scalar.
    """
    def __init__(self, rm_module=False):
        self.rm_module = rm_module

    def put(self, path, value, value_xfmr=None):
        """put a {path, value} pair to the map.. If the value is a
        json object or a list of objects, it will be expanded into individual
        scalar leaf values. Ignores root node of the RFC7951 json value if
        the root name matches the last path element's name.

        An optional value_xfmr function can be passed to transform the scalar
        value into any app specific form -- useful for creating wrapper values.
        value_xfmr receives one scalar value and should return one value (any).
        """
        value = remove_ietf_json_root(path, value)
        self.add_value(path, value, value_xfmr)

    def add_value(self, path, value, value_xfmr=None):
        """add_value stores a {path, value} pair in the map. If value is a json object
        or a list of objects, it will be expanded into individual scalar leaf values.
        """
        if self.rm_module:
            path = remove_module_name_from_xpath(path)

        if isinstance(value, dict):
            # Remove the sufix yang module name if present.
            value = remove_module_names_and_sort({}, value)
            for attr, val in value.items():
                sub_path = path + "/" + attr
                self.add_value(sub_path, val, value_xfmr)
        elif self.is_objlist(value):
            self.add_objlist(path, value, value_xfmr)
        elif value_xfmr:
            self[path] = value_xfmr(value)
        else:
            self[path] = value

    def add_objlist(self, path, obj_list, value_xfmr=None):
        """add_objlist expands the list of json objects into individual scalar leaf
        value pairs and records them. Won't record values for the key attribute paths.

        List key name/values are resolved by inspecting individual json objects in the list.
        All top level non container/list attributes are treated as key attributes. This is
        inline with openconfig yang convention. E.g, for the following input, only "name" is
        identified as key; "config" and "state" will not.
        path    = "/openconfig-interfaces:interfaces/interface"
        obj_list=[{"name":"Eth0", "config":{...}, "state":{...}}{"name":"Eth1", "config":{...}}]

        Leaf paths added to the map will be:
        "/openconfig-interfaces:interfaces/interface[name=Eth0]/config/..."
        "/openconfig-interfaces:interfaces/interface[name=Eth0]/state/..."
        "/openconfig-interfaces:interfaces/interface[name=Eth1]/config/..."

        This logic works only for openconfig yang data and not for ietf or sonic yang data.
        Raises a ValueError if the path does not start with "/openconfig-".
        """
        if not path.startswith("/openconfig-"):
            raise ValueError("Cannot handle list of objects for non-openconfig path")
        for obj in obj_list:
            if not isinstance(obj, dict):
                raise ValueError("Expecting only list of dict at {}".format(path))
            key_dict = {}
            sub_dict = {}
            # Segregate key and non-key attributes.
            for name, value in obj.items():
                if isinstance(value, list):
                    # TODO maybe remove this check -- it is an oc-yang specific logic
                    raise ValueError("Unexpected list at {}/{}".format(path, name))
                if isinstance(value, dict):
                    sub_dict[name] = value
                else:
                    key_dict[name] = value
            # Key values will are appended to the path to get the obj instance xpath.
            # Non-key values will be traversed recursively to collect scalars.
            inst_path = path + _format_xpath_keys(key_dict)
            self.add_value(inst_path, sub_dict, value_xfmr)
            self.add_value(inst_path, key_dict, value_xfmr)

    def is_objlist(self, value):
        return isinstance(value, list) and len(value) != 0 and isinstance(value[0], dict)

    def __str__(self):
        lines = ""
        for p, v in self.items():
            lines += "{} : {}\n".format(p, v)
        return lines


def remove_ietf_json_root(path, value):
    """remove_ietf_json_root returns child value of root node from the RFC7951 json.
    Returns the unmodified input if the root node not found or it does not match
    the last path element name.

    Examples:
    "/X/config",  {"config":{"id":111}}              -> {"id":111}
    "/X/id",      {"id":222}                         -> 222
    "/X[id=333]", {"X":[{"id":333, "config":{...}}]} -> [{"id":333, "config":{...}}]
    "/X/config",  {"id":444}                         -> {"id":444}
    "/X/config",  {"config":{...}, "state":{...}}    -> {"config":{...}, "state":{...}}
    """
    if not isinstance(value, dict) or len(value) != 1:
        return value
    p = get_gnmi_path(path)
    elems = p.elem  #pylint: disable=no-member
    if len(elems) == 0:
        return value
    # Match last path elem and root node with & without namespace prefix.
    namespace, name = get_elem_name_at(p, -1)
    if namespace and namespace+":"+name in value:
        value = value[namespace+":"+name]
    elif name in value:
        value = value[name]
    # If the last path elem has keys, the value could be a list of single object.
    if elems[-1].key:
        if isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict):
            value = value[0]
    return value


def onchange_sub(dut, param, timeout=60, new_conn=False, target='', conn_obj=''):
    """
    Generic Subscribe function.
    """
    if new_conn:
        conn_obj = get_gnmi_conn(dut, new_conn=new_conn)
    return conn_obj.gnmi_subscribe_onchange(param, timeout, target=target)

def gnmi_log_fail(msg):
    st.report_fail("msg", msg)


def gnmi_log_pass(msg=None):
    if msg:
        st.report_pass("msg", msg)
    else:
        st.report_pass("test_case_passed")

def verify_onchange(rpc, path=None, val=None, sync_res=False, feature="gNMI"):
    """
    Generic ON_CHANGE verify method.
    """
    if path:
        sync_val = {}
        path_li = utils.make_list(path)
        val_li = utils.make_list(val)

        for p, v in zip(path_li, val_li):
            sync_val[p] = v

        st.log(sync_val)

        if sync_res:
            st.log("*** Validating Initial Sync (sync_response=True) ***")
            if not rpc.verify(sync_val, [], True):
                gnmi_log_fail("{} ON_CHANGE: Test for Initial Sync failed.".format(feature))
        else:
            st.log("*** Validating Updates (sync_response=False) ***")
            if not rpc.verify(sync_val):
                gnmi_log_fail("{} ON_CHANGE: Test for updates failed (post Initial sync)".format(feature))
    return True

def get_elem_name_at(p, index):
    """get_elem_name_at returns the (namespace, name) tuple at given index from a gnmi path.
    If the element did not had a namespace, parent element's namespace is returned.
    """
    namespace, name = split_name(p.elem[index].name)
    if namespace:
        return namespace, name
    for ele in reversed(p.elem[:index]):
        namespace, _ = split_name(ele.name)
        if namespace:
            break
    return namespace, name


def split_name(name):
    """split_name returns (namespace, name) tuple for the yang node name.
    Namespace will be None if the node name is not qualified.
    """
    parts = name.split(":", 2)
    if len(parts) == 1:
        return None, parts[0]
    return parts[0], parts[1]


def remove_module_name_from_xpath(path):
    # return path
    rv = []
    for e in path.split("/"):
        if ":" in e:
            rv.append(e.split(":", 1)[1])
        else:
            rv.append(e)
    frv = '/'.join(rv)
    return frv
