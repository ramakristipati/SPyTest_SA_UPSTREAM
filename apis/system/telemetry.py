# This file contains the list of API's for operations of gNMI Telemetry Subscribe
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import signal
import os
import re
import time
import json
import socket
import pprint
import traceback

from spytest import st
from spytest import env
from spytest.gnmi.wrapper import yamlParser

from apis.system.gnmi import gnmi_cli, get_docker_command, dialout_server_cli

import utilities.utils as util_obj
from utilities.common import delete_file
from utilities.utils import erase_file_content, has_value

class Subscribe:

    def __init__(self, dut, xpath, file_name, **kwargs):
        """
        gNMI Subscription
        :param dut: DUT
        :param xpath: Single or list of uris
        :param file_name: Re-direct file name
        :param mode: remote | local | dialout
        :param grouping: single request for multiple xpaths (default: False)
        :param file_path: re-direct file path (default: /tmp)
        :param file_format: re-direct file format (default: txt)
        :param delay: Delay for each uri to subscribe (default: 10)
        :param port: gnmi port (default: 8080)
        :param query_type:  poll | once | stream (default: stream)
        :param stream_type: ON_CHANGE | SAMPLE | TARGET_DEFINED (default: ON_CHANGE)
        :param sample_interval: Sample interval (default: 10)
        :param skip_dialout_request: Enable only dialout listen capability (default: False)
        :param dialout_options: Extra options for dialout (port, allow_no_client_auth, log_levle, ...)
        """
        self.dut = dut
        self.xpath_list = util_obj.make_list(xpath)
        self.file_name = file_name
        self.mode = kwargs.get("mode", env.get("DEFAULT_GNMI_SUBSCRIBE_MODE", "remote"))
        self.grouping = bool(kwargs.get("grouping", env.get("DEFAULT_GNMI_SUBSCRIBE_GROUPING", False)))
        self.file_path = kwargs.get('file_path', '/tmp')
        self.file_format = kwargs.get('file_format', 'txt')
        self.delay = kwargs.get('delay', 10)
        self.port = kwargs.get('port', 8080)
        self.query_type = kwargs.get("query_type", 'stream')
        self.stream_type = kwargs.get("stream_type", env.get("DEFAULT_GNMI_SUBSCRIBE_STREAM_TYPE", "ON_CHANGE"))
        self.sample_interval = kwargs.get("sample_interval", 10)
        self.skip_dialout_request = kwargs.get('skip_dialout_request', False)
        self.dialout_options = kwargs.get('dialout_options', {})
        self.data = {}
        self._subscribe_(kwargs)

    def __del__(self):
        self.unsubscribe()

    def _subscribe_(self, kwargs):
        """
        gNMI Subscription
        This is auto-called while creating the class object.
        """
        ip = st.get_mgmt_ip(self.dut)
        if self.mode == 'dialout':
            host_ip = get_host_ip()
            if self.grouping:
                rv = self.dialout_add(self.file_name, self.xpath_list, **self.dialout_options)
                if not self.skip_dialout_request:
                    rv.update(self.dialout_req(xpath=self.xpath_list, file_name=self.file_name, host_ip=host_ip, host_port=rv['port'],interval=self.sample_interval if self.stream_type == "SAMPLE" else 0))
                self.data[self.file_name] = [rv, rv['redirect_file']]
                st.wait(self.delay, "Post {} subscribe".format(self.stream_type))
            else:
                for i, each_xpath in enumerate(self.xpath_list, start=1):
                    each_file_name = "{}_{}".format(self.file_name, i)
                    rv = self.dialout_add(each_file_name, each_xpath, **self.dialout_options)
                    if not self.skip_dialout_request:
                        rv.update(self.dialout_req(xpath=each_xpath, file_name=each_file_name, host_ip=host_ip, host_port=rv['port'],interval=self.sample_interval if self.stream_type == "SAMPLE" else 0))
                    self.data[each_xpath] = [rv, rv['redirect_file']]
                    st.wait(self.delay, "Post {} subscribe for '{}'".format(self.stream_type, each_xpath))
        else:
            if self.grouping:
                st.log("\n\n\t{} Subscription request group:\n{}\n".format(self.stream_type, pprint.pformat(self.xpath_list, width=2)))
                redirect_file = os.path.join(self.file_path, "{}.{}".format(self.file_name, self.file_format))
                on_change_dict = dict(query_type=self.query_type, ip_address=ip, port=self.port, mode=self.mode,
                                        xpath='"{}"'.format('","'.join(self.xpath_list)),
                                        streaming_type=self.stream_type, file_name=redirect_file, background=True,
                                        gnmi_utils_path=self.file_path)
                delete_file(redirect_file)
                rv = gnmi_cli(self.dut, **on_change_dict)
                self.data[redirect_file] = [rv, redirect_file]
                st.wait(self.delay, "Post {} subscribe".format(self.stream_type))
            else:
                for i, each_xpath in enumerate(self.xpath_list, start=1):
                    st.log("\n\n\t{} Subscription request: {}\n".format(self.stream_type, each_xpath))
                    each_xpath = each_xpath.strip()
                    redirect_file = os.path.join(self.file_path, "{}_{}.{}".format(self.file_name, i, self.file_format))
                    on_change_dict = dict(query_type=self.query_type, ip_address=ip, port=self.port, xpath=each_xpath,
                                        mode=self.mode, streaming_type=self.stream_type, file_name=redirect_file,
                                        background=True, gnmi_utils_path=self.file_path)
                    delete_file(redirect_file)
                    rv = gnmi_cli(self.dut, **on_change_dict)
                    self.data[each_xpath] = [rv, redirect_file]
                    st.wait(self.delay, "Post {} subscribe".format(self.stream_type))
        st.debug(pprint.pformat(self.data, width=2), dut=self.dut)
        return self.data

    def _get_data_(self, uri):
        if self.data.get(uri):
            return self.data[uri][0]

    def _get_pid_(self, uri):
        if self.data.get(uri):
            return self.data[uri][0]['pid']

    def _get_file_(self, uri):
        if self.data.get(uri):
            return self.data[uri][1]

    def unsubscribe(self, uri=None):
        """
        gNMI UN-Subscription
        This method will auto call during object getting destroy.
        Also we can use this method to un-subscribe the individual URI if want in the middle to test.
        :param uri: URI should pass un-subscribe.
        """
        uris = [uri] if uri else list(self.data.keys())
        for each_uri in uris:
            pid, file_path = self._get_pid_(each_uri), self._get_file_(each_uri)
            st.log("\n\n\t{} Un-Subscription/kill request: {}\n".format(self.stream_type, pid))
            data = self._get_data_(each_uri)
            del self.data[each_uri]
            if self.mode in ['remote', 'dialout']:
                if self.mode == 'dialout' and data is not None:
                    self.dialout_req(action='DELETE', **data)
                    st.wait(0.5)
                try:
                    os.killpg(pid, signal.SIGTERM)
                except Exception as e:
                    st.error(e)
                st.wait(0.5)
                st.log("Deleting file - {}".format(file_path))
                delete_file(file_path)
            else:
                cmd = "kill -9 {}".format(pid)
                st.config(self.dut, '{} -c "{}"'.format(get_docker_command(), cmd))
                cmd = "rm -rf {}".format(file_path)
                st.config(self.dut, '{} -c "{}"'.format(get_docker_command(), cmd))

    def get_payload(self, uri, erase=False, poll=1, delay=1):
        rvs = self.get_all_payloads(uri, erase, poll, delay)
        rv = rvs[-1] if rvs and len(rvs) else {}
        st.debug('get_playload: {}'.format(pprint.pformat(rv, width=2)), dut=self.dut)
        return rv

    def get_all_payloads(self, uri, erase=False, poll=1, delay=1):
        """
        Get gNMI Subscription notification data
        Use this method get and process the re-direct data to test.
        :param uri: URI
        :param erase: Do we need to clear content of the re-direct file (default: False)
        :param poll: poll to get the data from the re-direct file if reads empty file. (default: 1)
        :param delay: Poll delay.(default: 1)
        :return: data
        """
        file_name = self._get_file_(uri)
        rvs = []
        if self.mode == 'remote' or self.mode == "dialout":
            for i, _ in enumerate(range(poll), start=1):
                st.log("Poll - {} : Reading : {}".format(i, file_name))
                rvs = self._parse_output_file(file_name)
                if rvs and len(rvs):
                    break
                st.wait(delay, "Waiting to get data")
            if erase:
                erase_file_content(file_name)
        return rvs

    def _parse_output_file(self, file_path):
        txt = ''
        rv = []
        try:
            with open(file_path, 'r') as fp:
                txt = fp.read().replace("\x00", '')
            st.debug("Output from file: {}\n{}".format(file_path, txt), dut=self.dut)
            if len(txt):
                if '== subscribeResponse:' in txt:
                    def _dget(o, name):
                        l = []
                        if o:
                           if isinstance(o, list):
                               for i in o:
                                   l.extend(_dget(i, name))
                           elif name in o:
                               if isinstance(o[name], list):
                                   l.extend(o[name])
                               else:
                                   l.append(o[name])
                        return l

                    def _parse_elem(h, ptr={}, val=None):
                        elems = _dget(h, 'elem')
                        for el in elems:
                            if 'name' in el:
                                last_key = el['name'][0]
                                if el == elems[-1] and val is not None and 'key' not in el:
                                    ptr.update({last_key: val})
                                else:
                                    ptr.update({last_key: {}})
                                    ptr = ptr[last_key]
                                if 'key' in el and 'value' in el['key'][0]:
                                    last_key = el['key'][0]['value'][0]
                                    if el == elems[-1] and val is not None:
                                        ptr.update({last_key: val})
                                    else:
                                        ptr.update({last_key: {}})
                                        ptr = ptr[last_key]
                        return ptr

                    recs = [json.loads(json.dumps(o['update'])) for o in [yamlParser(x) for x in re.split(r'== subscribeResponse:\s*', re.sub(r'\\(\w+)', r'\\\\\1', txt).replace('<', '').replace('>', '')) if x and x.startswith('update:')] if o['update']]
                    for rec in recs:
                        # print('Record:\n{}'.format(rec))
                        obj = {}
                        ptr = _parse_elem(_dget(rec, 'prefix'), obj)
                        data = _dget(rec, 'update')
                        val = _dget(_dget(data, 'val'), 'json_ietf_val')
                        ptr = _parse_elem(_dget(data, 'path'), ptr, val[0])
                        rv.append(obj)
                else:
                    for rec in re.sub(r'(})(\s*{)', r'\1<--Record-Break-->\2', txt).split('<--Record-Break-->'):
                        # print('Record:\n{}'.format(rec))
                        try:
                            jsStr = re.sub(r'^[^{]+', '', re.sub(r'[^}]+$', '', rec))
                            if len(jsStr):
                                rv.append(json.loads(jsStr))
                        except Exception:
                            st.log('DEBUG original txt: {}\n{}\n'.format(file_path, txt))
                            st.warn('Found record which not JSON string: {}'.format(rec), dut=self.dut)
                            rv.append(rec)
                st.log(rv, dut=self.dut)
        except Exception as e:
            st.log('DEBUG Error reading file: {}\n{}\n'.format(file_path, txt))
            st.error(e)
            st.debug(traceback.format_exc(), dut=self.dut)
            rv = txt
        return rv

    def verify_payload(self, uri, value, erase=True, poll=5, delay=10, expect_matched=1):
        """
        Verify gNMI Subscription notification data
        :param uri: URI
        :param value: Value to verify Dict | subset od dict | string
        :param erase: Do we need to clear content of the re-direct file (default: True)
        :param poll: poll to get the data from the re-direct file if reads empty file (default: 5)
        :param delay: Poll delay (default: 10)
        :param expect_matched: number of matched records | all (default: 1)
        :return: bool
        """
        st.log("\n\n\tValidating {} Notification data..\n".format(self.stream_type))
        # data = self.get_payload(uri, erase=erase, poll=poll, delay=delay)
        matched = 0
        rvs = self.get_all_payloads(uri, erase, poll, delay)
        st.log("Checking for : {}".format(value))
        for data in rvs:
            found = ( has_value(data, value)
                    if isinstance(data, dict) and isinstance(value, (dict, list))
                    else str(value) in str(data) )
            st.log("Value {}present in Object {}".format('' if found else 'not ', data))
            if found:
                matched += 1
        if str(expect_matched) == 'all' and len(rvs):
            expect_matched = len(rvs)
        return matched>0 and matched>=expect_matched


    def dialout_add(self, file_name, xpath_list, **kwargs):
        """
        Create new dialout listener
        :param file_name:
        :param :port:
        :return:
        """
        port = kwargs.get('port', get_free_port())
        st.log("\n\n\tAdd Dialout Listerner port: {}\n".format(port))
        out = {'port': port}
        if is_port_free(port):
            if not os.path.exists(self.file_path):
                os.makedirs(self.file_path)
            redirect_file = os.path.join(self.file_path, "{}_{}.{}".format(file_name, port, self.file_format))
            st.log("\n\n\t{} Subscription request:\n{}\n".format(self.stream_type, pprint.pformat(xpath_list, width=2)))
            on_change_dict = dict(  port=port, file_name=redirect_file, background=True,
                                    allow_no_client_auth=kwargs.get('allow_no_client_auth', True),
                                    insecure=kwargs.get('insecure', True),
                                    logtostderr=kwargs.get('logtostderr', True),
                                    logtostdout=kwargs.get('logtostdout', True),
                                    log_level=kwargs.get('log_level', 2),
                                    pretty=kwargs.get('pretty', False))
            delete_file(redirect_file)
            out.update({'redirect_file': redirect_file})
            out.update(dialout_server_cli(**on_change_dict))
            st.wait(2)
        else:
            out.update({'error': 'No free port', 'output': '', 'rc': 1, 'pid': ''})
            st.log("RESULT {}".format(out))
        return out

    def dialout_req(self, action='CREATE', **kwargs):
        """
        Send request to start dialout
        :param :action:
        :param :xpath:
        :param :file_name:
        :return:
        """
        xpath = kwargs.get('xpath', [])
        file_name = kwargs.get('file_name', '{}-{}'.format(self.stream_type, round(time.time() * 1000)))
        out = {'xpath': xpath, 'file_name': file_name}
        if action == 'DELETE':
            req = kwargs.get('req', {})
            if 'subscription' in req.keys():
                st.log('Dialout delete persistent-subscription: {0[subscription][id]} ... '.format(req))
                rc = st.open_config(self.dut, '/restconf/data/openconfig-telemetry:telemetry-system/subscriptions/persistent-subscriptions/persistent-subscription={0[subscription][id]}'.format(req), action=action)
                st.log('Result: {0[status]} :: {0[output]}'.format(rc))
            if 'destination' in req.keys():
                st.log('Dialout delete destination-group: {0[destination][id]} ... '.format(req))
                st.open_config(self.dut, '/restconf/data/openconfig-telemetry:telemetry-system/destination-groups/destination-group={0[destination][id]}'.format(req), action=action)
                st.log('Result: {0[status]} :: {0[output]}'.format(rc))
            if 'sensor' in req.keys():
                st.log('Dialout delete sensor-group: {0[sensor][id]} ... '.format(req))
                rc = st.open_config(self.dut, '/restconf/data/openconfig-telemetry:telemetry-system/sensor-groups/sensor-group={0[sensor][id]}'.format(req), action=action)
                st.log('Result: {0[status]} :: {0[output]}'.format(rc))
        else:
            req = self.dialout_data_req(file_name, **kwargs)
            st.log('Dialout request for "{0}": {1}\n'.format(file_name, xpath))
            rc = st.open_config(self.dut, '/restconf/data/openconfig-telemetry:telemetry-system/sensor-groups', action=action, data=req['sensor']['data'])
            st.log('Adding sensor-group "{0[sensor][id]}": {1[operation]}-{1[status]} {1[output]}\n'.format(req, rc))
            if rc['status'] >= 300 or rc['status'] is False:
                st.warn('rc: {}'.format(pprint.pformat(rc)), dut=self.dut)
            rc = st.open_config(self.dut, '/restconf/data/openconfig-telemetry:telemetry-system/destination-groups', action=action, data=req['destination']['data'])
            st.log('Adding destination-group "{0[destination][id]}": {1[operation]}-{1[status]} {1[output]}\n'.format(req, rc))
            if rc['status'] >= 300 or rc['status'] is False:
                st.warn('rc: {}'.format(pprint.pformat(rc)), dut=self.dut)
            rc = st.open_config(self.dut, '/restconf/data/openconfig-telemetry:telemetry-system/subscriptions/persistent-subscriptions', action=action, data=req['subscription']['data'])
            st.log('Adding subscription "{0[sensor][id]}": {1[operation]}-{1[status]} {1[output]}\n'.format(req, rc))
            if rc['status'] >= 300 or rc['status'] is False:
                st.warn('rc: {}'.format(pprint.pformat(rc)), dut=self.dut)
            out.update({'req': req})
            cur_cfg = st.open_config(self.dut, '/restconf/data/openconfig-telemetry:telemetry-system')
            st.debug("Current telemetry-system config:\n{}".format(pprint.pformat(cur_cfg['output'])), dut=self.dut)
        return out

    def dialout_data_req(self, name, **kwargs):
        """
        Compose dialout request data
        :param name:
        :param :xpath:
        :param :host_ip:
        :param :host_port:
        :param :interval:
        :param :suppress_redundant:
        :param :subscription_protocol:
        :param :encoding:
        :param :sensor_group:
        :param :destination_group:
        :param :subscription_name:
        :return:
        """
        xpath = kwargs.get('xpath', [])
        sgId = kwargs.get('sensor_group',"sg.{}".format(name))
        dgId = kwargs.get('destination_group',"dg.{}".format(name))
        subId = kwargs.get('subscription_name',"sub.{}".format(name))
        host_ip = kwargs.get('host_ip', get_host_ip())
        host_port = kwargs.get('host_port', get_free_port())
        interval = str(kwargs.get('interval', 0))
        suppress_redundant = bool(kwargs.get('suppress_redundant', True))
        subscription_protocol = kwargs.get('subscription_protocol', "STREAM_GRPC")
        encoding = kwargs.get('encoding', 'ENC_JSON_IETF')
        sensor_path = []
        for each_xpath in util_obj.make_list(xpath):
            sensor_path.append({
                "path": each_xpath,
                "config": { "path": each_xpath }
            })
        sgData = {
            "openconfig-telemetry:sensor-group": [{
                "sensor-group-id": sgId,
                "config": {
                    "sensor-group-id": sgId
                },
                "sensor-paths": {
                    "sensor-path": sensor_path
                }
            }]
        }
        dgData = {
            "openconfig-telemetry:destination-group": [{
                "group-id": dgId,
                "config": {
                    "group-id": dgId
                },
                "destinations": {
                    "destination": [{
                        "destination-address": host_ip,
                        "destination-port": host_port,
                        "config": {
                            "destination-address": host_ip,
                            "destination-port": host_port
                        }
                    }]
                }
            }]
        }
        subData = {
            "openconfig-telemetry:persistent-subscription": [{
                "name": subId,
                "config": {
                    "name": subId,
                    "protocol": subscription_protocol,
                    "encoding": encoding
                },
                "sensor-profiles": {
                    "sensor-profile": [{
                        "sensor-group": sgId,
                        "config": {
                            "sensor-group": sgId,
                            "sample-interval": interval,
                            "suppress-redundant": suppress_redundant
                        }
                    }]
                },
                "destination-groups": {
                    "destination-group": [{
                        "group-id": dgId,
                        "config": {
                            "group-id": dgId
                        }
                    }]
                }
            }]
        }
        return {
            'sensor': {'id': sgId, 'data': sgData},
            'destination': {'id': dgId, 'data': dgData},
            'subscription': {'id': subId, 'data': subData}
        }



# Auxiliary functions

def check_docker_state(dut, docker='telemetry'):
    """

    :param dut:
    :param docker:
    :return:
    """
    cmd = "docker inspect -f '{{.State.Running}}' %s" % docker
    out = st.config(dut, cmd, type='click')
    if 'true' in out:
        st.log("Docker {} is running.".format(docker))
        return True
    else:
        st.log("Docker {} NOT is running.".format(docker))
        return False

def get_host_ip():
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        return host_ip
    except:
        raise ValueError("Unable to get host IP")


def is_port_free(port, sock=None):
    """
    Verify if port is available
    :param port:
    :return:
    """
    need_closing = False
    if sock is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        need_closing = True
    try:
        sock.bind(('', port))
        if need_closing:
            sock.close()
    except OSError:
        return False
    return True


def get_free_port(port=8000, max_port=65535):
    """
    Get an available port start from range
    :param port:
    :param max_port:
    :return:
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while port <= max_port:
        if is_port_free(port, sock):
            sock.close()
            return port
        else:
            port += 1
    sock.close()
    return None
