# This file contains the list of API's for operations of gNMI ON_CHANGE
# Author : Prudvi Mangadu (prudvi.mangadu@broadcom.com)

import signal
import os
import socket
import atexit
import time
import pprint

from spytest import st
from spytest import env

from apis.system.gnmi import gnmi_cli, get_docker_command, dialout_server_cli

import utilities.utils as util_obj
from utilities.common import delete_file
from utilities.utils import read_json, has_value, erase_file_content

dialout_listeners = {}
subscribe_listeners = {}
dut_set = set()

def subscribe(dut, xpath, file_name, **kwargs):
    """
    gNMI ON_CHANGE Subscription
    :param dut:
    :param xpath:
    :param file_name:
    :param :mode:
    :param :grouping:
    :param :file_path:
    :param :file_format:
    :param :delay:
    :param :skip_dialout_request:
    :return:
    """
    defautlt_mode = env.get("DEFAULT_GNMI_SUBSCRIBE_MODE", "remote")
    mode = str(kwargs.get("mode", defautlt_mode)).lower()
    defautlt_grouping = env.get("DEFAULT_GNMI_SUBSCRIBE_GROUPING", False)
    grouping = bool(kwargs.get("grouping", defautlt_grouping))
    file_path = kwargs.get('file_path', '/tmp')
    file_format = kwargs.get('file_format', 'txt')
    delay = kwargs.get('delay', 10)
    skip_dialout_request = kwargs.get('skip_dialout_request', False)

    st.log("\n\n\tON_CHANGE Subscription request: {}\n".format(xpath))
    out = {}
    ip = st.get_mgmt_ip(dut)
    xpath_list = util_obj.make_list(xpath)
    if mode == 'dialout':
        host_ip = get_host_ip()
        if grouping:
            rv = dialout_add(file_name, **kwargs)
            if not skip_dialout_request:
                rv.update(dialout_req(dut=dut, xpath=xpath_list, file_name=file_name, host_ip=host_ip, host_port=rv['port'], **kwargs))
            rv.update({'mode': mode, 'dut': dut})
            out[file_name] = [rv, rv['file_path']]
            subscribe_listeners.update({rv['file_path']: rv})
            st.wait(delay, "Post ON_CHANGE subscribe")
        else:
            for i, each_xpath in enumerate(xpath_list, start=1):
                each_file_name = "{}_{}".format(file_name, i)
                rv = dialout_add(each_file_name, **kwargs)
                if not skip_dialout_request:
                    rv.update(dialout_req(dut=dut, xpath=each_xpath, file_name=each_file_name, host_ip=host_ip, host_port=rv['port'], **kwargs))
                rv.update({'mode': mode, 'dut': dut})
                out[each_xpath] = [rv, rv['file_path']]
                subscribe_listeners.update({rv['file_path']: rv})
                st.wait(delay, "Post ON_CHANGE subscribe for '{}'".format(each_xpath))
    elif mode in ['local', 'remote']:
        if grouping:
            redirect_file = os.path.join(file_path, "{}.{}".format(file_name, file_format))
            on_change_dict = dict(query_type="stream", ip_address=ip, port=8080, mode=mode,
                                    xpath='"{}"'.format('","'.join(xpath_list)),
                                    streaming_type='ON_CHANGE', file_name=redirect_file, background=True,
                                    gnmi_utils_path=file_path)
            delete_file(redirect_file)
            rv = gnmi_cli(dut, **on_change_dict)
            rv.update({'mode': mode, 'dut': dut})
            out[file_name] = [rv, redirect_file]
            subscribe_listeners.update({redirect_file: rv})
            st.wait(delay, "Post ON_CHANGE subscribe")
        else:
            for i, each_xpath in enumerate(xpath_list, start=1):
                each_xpath = each_xpath.strip()
                redirect_file = os.path.join(file_path, "{}_{}.{}".format(file_name, i, file_format))
                on_change_dict = dict(query_type="stream", ip_address=ip, port=8080, xpath='"{}"'.format(each_xpath), mode=mode,
                                    streaming_type='ON_CHANGE', file_name=redirect_file, background=True,
                                    gnmi_utils_path=file_path)
                delete_file(redirect_file)
                rv = gnmi_cli(dut, **on_change_dict)
                rv.update({'mode': mode, 'dut': dut})
                out[each_xpath] = [rv, redirect_file]
                subscribe_listeners.update({redirect_file: rv})
                st.wait(delay, "Post ON_CHANGE subscribe for '{}'".format(each_xpath))
    return out


def unsubscribe(dut, pid, file_path, **kwargs):
    """
    gNMI ON_CHANGE UN-Subscription
    :param dut:
    :param pid:
    :param file_path:
    :param :mode:
    :return:
    """
    defautlt_mode = env.get("DEFAULT_GNMI_SUBSCRIBE_MODE", "remote")
    mode = str(kwargs.get('mode', defautlt_mode)).lower()
    st.log("\n\n\tON_CHANGE Un-Subscription/kill request: {}\n".format(pid))
    listener = subscribe_listeners.pop(file_path, {})
    if mode == 'remote':
        try:
            os.killpg(pid, signal.SIGTERM)
        except Exception as e:
            st.error(e)
        st.wait(0.5)
        st.log("Deleting file - {}".format(file_path))
        delete_file(file_path)
    elif mode == 'local':
        cmd = "kill -9 {}".format(pid)
        st.config(dut, '{} -c "{}"'.format(get_docker_command(), cmd))
        cmd = "rm -rf {}".format(file_path)
        st.config(dut, '{} -c "{}"'.format(get_docker_command(), cmd))
    elif mode == 'dialout' and dut == listener['dut']:
        dialout_req(action='DELETE', **listener)
        dialout_del(pid=pid, file_path=file_path)


@atexit.register
def cleanup():
    """
    Cleanup all subscribe listerners
    :return:
    """
    if len(subscribe_listeners):
        st.log("\n\n\tON_CHANGE cleanup subscribe listeners...\n")
        for file_path in list(subscribe_listeners.keys()):
            itm = subscribe_listeners.get(file_path)
            unsubscribe(itm['dut'], itm['pid'], file_path, mode=itm['mode'])
    dialout_cleanup()


def get_payload(file_name, mode='remote', erase=False):
    """
    Get gNMI ON_CHANGE Subscription notification data
    :param file_name:
    :param mode:
    :param erase:
    :return:
    """
    if mode == 'remote':
        st.log("Reading : {}".format(file_name))
        st.wait(0.2)
        out = read_json(file_name)
        if erase:
            st.wait(0.2)
            erase_file_content(file_name)
        return out


def verify_payload(file_name, value, mode='remote', erase=True):
    """
    Verify gNMI ON_CHANGE Subscription notification data
    :param file_name:
    :param value:
    :param mode:
    :param erase:
    :return:
    """
    st.log("\n\n\tValidating ON_CHANGE Notification data..\n")
    data = get_payload(file_name, mode=mode, erase=erase)
    st.log("Checking for : {}".format(value))
    if isinstance(data, dict) and isinstance(value, (dict, list)):
        return has_value(data, value)
    else:
        if str(value) in str(data):
            st.log("Value present in Object")
            return True
        else:
            st.error("Value not present in Object")
            return False


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


def dialout_data_req(name, **kwargs):
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


def dialout_req(**kwargs):
    """
    Send request to start dialout
    :param :dut:
    :param :action:
    :param :xpath:
    :param :file_name:
    :return:
    """
    dut = kwargs.get('dut')
    dut_set.add(dut)
    action = kwargs.get('action', 'CREATE').upper()
    xpath = kwargs.get('xpath', [])
    file_name = kwargs.get('file_name', 'ON_CHANGE-{}'.format(round(time.time() * 1000)))
    out = {'xpath': xpath, 'file_name': file_name}
    if action == 'DELETE':
        req = kwargs.get('req', {})
        if 'subscription' in req.keys():
            st.log('Dialout delete persistent-subscription: {0[subscription][id]} ... '.format(req))
            rc = st.open_config(dut, '/restconf/data/openconfig-telemetry:telemetry-system/subscriptions/persistent-subscriptions/persistent-subscription={0[subscription][id]}'.format(req), action=action)
            st.log('Result: {0[status]} :: {0[output]}'.format(rc))
        if 'destination' in req.keys():
            st.log('Dialout delete destination-group: {0[destination][id]} ... '.format(req))
            st.open_config(dut, '/restconf/data/openconfig-telemetry:telemetry-system/destination-groups/destination-group={0[destination][id]}'.format(req), action=action)
            st.log('Result: {0[status]} :: {0[output]}'.format(rc))
        if 'sensor' in req.keys():
            st.log('Dialout delete sensor-group: {0[sensor][id]} ... '.format(req))
            rc = st.open_config(dut, '/restconf/data/openconfig-telemetry:telemetry-system/sensor-groups/sensor-group={0[sensor][id]}'.format(req), action=action)
            st.log('Result: {0[status]} :: {0[output]}'.format(rc))
    else:
        req = dialout_data_req(file_name, **kwargs)
        st.log('Dialout request for "{0}": {1}\n'.format(file_name, xpath))
        rc = st.open_config(dut, '/restconf/data/openconfig-telemetry:telemetry-system/sensor-groups', action=action, data=req['sensor']['data'])
        st.log('Adding sensor-group "{0[sensor][id]}": {1[operation]}-{1[status]} {1[output]}\n'.format(req, rc))
        if rc['status'] >= 300 or rc['status'] is False:
            st.warn('rc: {}'.format(pprint.pformat(rc)), dut=dut)
        rc = st.open_config(dut, '/restconf/data/openconfig-telemetry:telemetry-system/destination-groups', action=action, data=req['destination']['data'])
        st.log('Adding destination-group "{0[destination][id]}": {1[operation]}-{1[status]} {1[output]}\n'.format(req, rc))
        if rc['status'] >= 300 or rc['status'] is False:
            st.warn('rc: {}'.format(pprint.pformat(rc)), dut=dut)
        rc = st.open_config(dut, '/restconf/data/openconfig-telemetry:telemetry-system/subscriptions/persistent-subscriptions', action=action, data=req['subscription']['data'])
        st.log('Adding subscription "{0[sensor][id]}": {1[operation]}-{1[status]} {1[output]}\n'.format(req, rc))
        if rc['status'] >= 300 or rc['status'] is False:
            st.warn('rc: {}'.format(pprint.pformat(rc)), dut=dut)
        out.update({'req': req})
        cur_cfg = st.open_config(dut, '/restconf/data/openconfig-telemetry:telemetry-system')
        st.debug("Current telemetry-system config:\n{}".format(pprint.pformat(cur_cfg['output'])), dut=dut)
    return out


def dialout_add(file_name, **kwargs):
    """
    Create new dialout listener
    :param file_name:
    :param :file_path:
    :param :file_format:
    :param :port:
    :return:
    """
    file_path = kwargs.get('file_path', '/tmp')
    file_format = kwargs.get('file_format', 'txt')
    port = kwargs.get('port', get_free_port())

    st.log("\n\n\tON_CHANGE Add Dialout Listerner port: {}\n".format(port))
    out = {'port': port, 'mode': 'dialout'}
    if is_port_free(port):
        if not os.path.exists(file_path):
            os.makedirs(file_path)
        redirect_file = os.path.join(file_path, "{}_{}.{}".format(file_name, port, file_format))
        on_change_dict = dict(  port=port, file_name=redirect_file, background=True,
                                allow_no_client_auth=kwargs.get('allow_no_client_auth', True),
                                insecure=kwargs.get('insecure', True),
                                logtostderr=kwargs.get('logtostderr', True),
                                logtostdout=kwargs.get('logtostdout', True),
                                log_level=kwargs.get('log_level', 2),
                                pretty=kwargs.get('pretty', True))
        delete_file(redirect_file)
        out.update({'file_path': redirect_file})
        out.update(dialout_server_cli(**on_change_dict))
        dialout_listeners.update({port: out})
        st.wait(2)
    else:
        out.update({'error': 'No free port', 'output': '', 'rc': 1, 'pid': ''})
        st.log("RESULT {}".format(out))
    return out


def dialout_del(**kwargs):
    """
    Delete a dialout listerner by pid, file_path, or listening port
    :param :pid:
    :param :file_path:
    :param :port:
    :return:
    """
    pid = kwargs.get('pid', None)
    file_path = kwargs.get('file_path', None)
    port = kwargs.get('port', None)
    rec = {}
    if port and dialout_listeners[port]:
        rec.update(dialout_listeners[port])
    elif pid or file_path:
        for p, itm in dialout_listeners.items():
            if itm['pid'] == pid or itm['file_path'] == file_path:
                rec.update(dialout_listeners.pop(p, {}))
                break
    if rec['pid'] and rec['file_path']:
        st.log("\n\n\tON_CHANGE delete/kill dialout listener: {}\n".format(rec))
        try:
            os.killpg(rec['pid'], signal.SIGTERM)
        except Exception as e:
            st.error(e)
        st.wait(0.5)
        st.log("Deleting file - {}".format(rec['file_path']))
        delete_file(rec['file_path'])
    else:
        st.log("\n\n\tON_CHANGE delete/kill dialout listener not found!: {}\n".format(kwargs))


def dialout_cleanup():
    """
    Cleanup all dialout listerners
    :return:
    """
    if len(dialout_listeners):
        st.log("\n\n\tON_CHANGE cleanup dialout listeners...\n")
        for port in list(dialout_listeners.keys()):
            dialout_del(port=port)
    for dut in dut_set:
        st.open_config(dut, '/restconf/data/openconfig-telemetry:telemetry-system', action='DELETE')

