import json

from spytest import st
from apis.system.interface import interface_status_show, clear_interface_counters
from utilities.common import filter_and_select
from utilities.common import make_list
from utilities.utils import get_interface_number_from_name, get_supported_ui_type_list, convert_intf_name_to_component
from apis.system.rest import config_rest, delete_rest, get_rest

errors_list = ['error', 'invalid', 'usage', 'illegal', 'unrecognized']

try:
    import apis.yang.codegen.messages.qos as umf_qos
    from apis.yang.utils.common import Operation
except ImportError:
    pass

def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type

def config_pfc_asymmetric(dut, mode, interface = [], **kwargs):
    """
    To configure asymmetric mode on ports
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param type:
    :type on|off:
    :param interface:
    :type list():
    :param cli_type: 
    :type cli_type:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    if mode not in ['on','off'] or not interface:
        st.error("Mode can take on|off values only, interface cannot be empty")
        return False
    interface = make_list(interface)
    commands = list()
    if cli_type in get_supported_ui_type_list():
        for intf in interface:
            if mode == 'on':
                qos_obj = umf_qos.Interface(InterfaceId=intf, Asymmetric=True)
            else:
                qos_obj = umf_qos.Interface(InterfaceId=intf, Asymmetric=False)
            result = qos_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config priority-flow-control on interface {}'.format(result.data))
                return False
        return True
    if cli_type == 'click':
        for intf in interface:
            intf = st.get_other_names(dut, [intf])[0] if '/' in intf else intf
            commands.append("pfc config asymmetric {} {}".format(mode,intf))
    elif cli_type == 'klish':
        no_form = "" if mode == 'on' else "no"
        for intf in interface:
            intf_data = get_interface_number_from_name(intf)
            commands.append("interface {} {}".format(intf_data['type'], intf_data['number']))
            commands.append("{} priority-flow-control asymmetric".format(no_form))
            commands.append("exit")
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        asym = True if mode == 'on' else False
        config_data = {"openconfig-qos:config": {"asymmetric": asym}}
        for intf in interface:
            url = rest_urls['pfc_asymmetric_config'].format(intf)
            if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_data):
                st.error("Failed to configure asymmetric mode: {} on port: {}".format(mode, intf))
                return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if commands:
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    return True


def config_pfc_lossless_queues(dut, queues_list, ports_list, **kwargs):
    """
    To configure lossless priorities on port
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param queues_list:
    :type list:
    :param cli_type:
    :type cli_type:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    config = kwargs.get('config', True)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    ports = make_list(ports_list)
    queues = make_list(queues_list)
    if not queues:
        st.log('No dot1p value provided, so using klish')
        cli_type = 'klish'
    if cli_type in get_supported_ui_type_list():
        operation = Operation.CREATE
        for port in ports:
            for queue in queues:
                int_obj = umf_qos.Interface(InterfaceId=port)
                qos_obj = umf_qos.PfcPriority(Dot1p=int(queue),Enable=config, Interface=int_obj)
                if config:
                    result = qos_obj.configure(dut, operation=operation, cli_type=cli_type)
                else:
                    result = qos_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Config priority queues on interface {}'.format(result.data))
                    return False
        return True
    cli_type = 'klish' if skip_error and cli_type == 'click' else cli_type
    if cli_type == 'click':
        queues = ",".join([str(queue) for queue in queues]) if config else ""
        final_data = dict()
        temp_data = dict()
        for port in ports:
            port = st.get_other_names(dut, [port])[0] if '/' in port else port
            temp_data[port] = {"pfc_enable": queues}
        final_data['PORT_QOS_MAP'] = temp_data
        final_data = json.dumps(final_data)
        st.apply_json2(dut, final_data)
    elif cli_type == 'klish':
        commands = list()
        no_form = "" if config else "no"
        for port in ports:
            intf_data = get_interface_number_from_name(port)
            commands.append('interface {} {}'.format(intf_data['type'], intf_data['number']))
            if queues:
                commands.extend(['{} priority-flow-control priority {}'.format(no_form, queue) for queue in queues])
            else:
                commands.append('{} priority-flow-control priority'.format(no_form))
            commands.append('exit')
            response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
            if any(error.lower() in response.lower() for error in errors):
                st.error("The response is: {}".format(response))
                return False
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        message = "loss-less" if config else "lossy"
        for port in ports:
            for queue in queues:
                if config:
                    url = rest_urls['pfc_lossless_queue_config'].format(port)
                    config_data = {"openconfig-qos:pfc-priorities": {"pfc-priority": [{"dot1p": int(queue), "config": {"dot1p": int(queue), "enable": config}}]}}
                    if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_data):
                        st.error("Failed to configure the priority: {} as {} on port: {}".format(queue, message, port))
                        return False
                else:
                    url = rest_urls['pfc_dot1q_intf_config'].format(port, queue)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to configure the priority: {} on port: {}".format(queue, port))
                        return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def verify_pfc_asymmetric(dut, ports, mode, cli_type='',**kwargs):
    """
    To configure lossless priorities on port
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    Modified by: Gangadhara Sahu (gangadhara.sahu@broadcom.com)
    :param dut:
    :type dut:
    :param ports:
    :type list:
    :param mode:
    :type on/off:
    :param cli_type: forced to klish cli_type because click support only for assymetric & gnmi/rest not supported
    :type cli_type:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type) if 'symmetric_pfc' in kwargs else cli_type
    cli_type = force_cli_type_to_klish(cli_type=cli_type) if 'symmetric_pfc' not in kwargs and cli_type in get_supported_ui_type_list() else cli_type
    ports = make_list(ports)
    if cli_type == 'click':
        command = "pfc show asymmetric"
        output = st.show(dut, command, type=cli_type)
        for port in ports:
            entry = filter_and_select(output, ['pfc_asymmetric'], {'interface': port})
            if not (len(entry) and entry[0]['pfc_asymmetric'] in mode):
                st.error('Provided asymmetric mode: {} not matching with the actual mode: {} on port: {}'.format(mode, entry[0]['pfc_asymmetric'], port))
                return False
            else:
                st.log('Provided asymmetric mode: {} matching with the actual mode: {} on port: {}'.format(mode, entry[0]['pfc_asymmetric'], port))
                return True
    elif cli_type == 'klish':
        for port in ports:
            intf_data = get_interface_number_from_name(port)
            command = "show qos interface {} {}".format(intf_data['type'], intf_data['number'])
            output = st.show(dut, command, type=cli_type)
            if 'symmetric_pfc' in kwargs and kwargs['symmetric_pfc'] != "":
                entry = filter_and_select(output, None, {'pfc_priority': kwargs['symmetric_pfc']})
            else:
                entry = filter_and_select(output, None, {'pfc_asymmetric': mode})
            if not entry:
                if 'symmetric_pfc' not in kwargs:
                    st.error('Provided asymmetric mode: {} not matching with the actual mode on port: {}'.format(mode, port))
                else:
                    st.error('Provided symmetric pfc-priority: {} not matching with the actual pfc-priority on port: {}'.format(kwargs['symmetric_pfc'], port))
                return False
            else:
                if 'symmetric_pfc' not in kwargs:
                    st.log('Provided asymmetric mode: {} matching with the actual mode on port: {}'.format(mode, port))
                else:
                    st.log('Provided symmetric pfc-priority: {} matching with the actual pfc-priority on port: {}'.format(kwargs['symmetric_pfc'], port))
                return True
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        asym_mode = True if mode=='on' else False
        verify_payload = {"openconfig-qos:asymmetric": asym_mode}
        for port in ports:
            url = rest_urls['pfc_asymmetric_get'].format(port)
            out = get_rest(dut, rest_url = url)
            if not out['output'] == verify_payload:
                st.error('Provided asymmetric mode: {} not matching with the actual mode on port: {}'.format(mode, port))
                return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def start_pfc_wd(dut,action,detection_time,restoration_time,interface=[], **kwargs):
    """
    To configure PFC Watch-Dog parameters
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param action:
    :type action:
    :param detection_time:
    :type detection_time:
    :param restoration_time:
    :type restoration_time:
    :param interface:
    :type interface:
    """
    if not interface:
        st.error("Please provide atleast one interface")
        return False
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    interfaces = make_list(interface)
    commands = list()
    if cli_type in get_supported_ui_type_list():
        for intf in interface:
            qos_obj = umf_qos.Interface(InterfaceId=intf, Action=action.upper(), DetectionTime=int(detection_time),
                                        RestorationTime=int(restoration_time))
            result = qos_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config priority-flow-control on interface {}'.format(result.data))
                return False
        return True
    if cli_type == 'click':
        for intf in interfaces:
            intf = st.get_other_names(dut, [intf])[0] if '/' in intf else intf
            commands.append("pfcwd start --action {} --restoration-time {} {} {} ".format(action,restoration_time,intf,detection_time))
    elif cli_type == 'klish':
        for intf in interfaces:
            intf_data = get_interface_number_from_name(intf)
            commands.append("interface {} {}".format(intf_data['type'], intf_data['number']))
            commands.append("priority-flow-control watchdog action {}".format(action))
            commands.append("priority-flow-control watchdog on detect-time {}".format(detection_time))
            commands.append("priority-flow-control watchdog restore-time {}".format(restoration_time))
            commands.append("exit")
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        config_data = {"openconfig-qos:config": {"action": action.upper(), "detection-time": int(detection_time), "restoration-time": int(restoration_time)}}
        for intf in interfaces:
            url= rest_urls['pfc_wd_interface_config'].format(intf)
            if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_data):
                st.error("Failed to configure PFC watch dog parameters on port: {}".format(intf))
                return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if commands:
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    return True


def stop_pfc_wd(dut,interface=[], **kwargs):
    """
    To configure PFC Watch-Dog as OFF
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param interface:
    :type interface:
    """
    if not interface:
        st.error("Please provide atleast one interface")
        return False
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    interfaces = make_list(interface)
    commands = list()
    if cli_type in get_supported_ui_type_list():
        for intf in interface:
            qos_obj = umf_qos.Interface(InterfaceId=intf)
            result = qos_obj.unConfigure(dut, target_path='/pfc/watchdog/config/', cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: unConfig priority-flow-control on interface {}'.format(result.data))
                return False
        return True
    if cli_type == 'click':
        for intf in interfaces:
            intf = st.get_other_names(dut, [intf])[0] if '/' in intf else intf
            commands.append("pfcwd stop {}".format(intf))
    elif cli_type == 'klish':
        for intf in interfaces:
            intf_data = get_interface_number_from_name(intf)
            commands.append("interface {} {}".format(intf_data['type'], intf_data['number']))
            commands.append("priority-flow-control watchdog off")
            commands.append("exit")
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        for intf in interfaces:
            url = rest_urls['pfc_wd_interface_config'].format(intf)
            if not delete_rest(dut, rest_url= url):
                st.error("Failed to stop PFC watch dog on {}".format(intf))
                return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if commands:
        response = st.config(dut, commands, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    return True


def pfc_wd_counter_poll_interval(dut, interval, **kwargs):
    """
    To configure PFC Watch-Dog polling interval
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param interval:
    :type interval:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    command = ''
    config = kwargs.get('config', True)
    if cli_type in get_supported_ui_type_list():
        qos_obj = umf_qos.Qos(PollInterval=interval)
        if config:
            result = qos_obj.configure(dut, cli_type=cli_type)
        else:
            result = qos_obj.unConfigure(dut, target_attr=qos_obj.PollInterval, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config priority-flow-control on interface {}'.format(result.data))
            return False
        return True
    if cli_type == 'click':
        command = "pfcwd interval {}".format(interval)
    elif cli_type == 'klish':
        command = "priority-flow-control watchdog polling-interval {}".format(interval)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['pfc_wd_global_config']
        poll_config = {"openconfig-qos:pfc-watchdog": {"poll": {"config": {"poll-interval": int(interval)}}}}
        if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=poll_config):
            st.error('Failed to configure PFC Watch-Dog polling interval as: {}'.format(interval))
            return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if command:
        response = st.config(dut, command, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    return True


def pfc_wd_counter_poll_config(dut, enable, **kwargs):
    """
    To enable/disable PFC Watch-Dog counter poll
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param dut:
    :type True/False:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error = kwargs.get('skip_error', False)
    errors = make_list(kwargs.get('error_msg')) if kwargs.get('error_msg') else errors_list
    command = ''
    config = kwargs.get('config', True)
    if cli_type in get_supported_ui_type_list():
        mode = 'ENABLE' if enable else 'DISABLE'
        qos_obj = umf_qos.Qos(CounterPoll=mode)
        if config:
            result = qos_obj.configure(dut, cli_type=cli_type)
        else:
            result = qos_obj.unConfigure(dut, target_attr=qos_obj.CounterPoll, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config priority-flow-control on interface {}'.format(result.data))
            return False
        return True
    if cli_type == 'click':
        mode = 'enable' if enable else 'disable'
        command = "pfcwd counter_poll {}".format(mode)
    elif cli_type == 'klish':
        command = 'priority-flow-control watchdog counter-poll' if enable else 'no priority-flow-control watchdog counter-poll'
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['pfc_wd_global_config']
        mode = 'ENABLE' if enable else 'DISABLE'
        config_data = {"openconfig-qos:pfc-watchdog": {"flex": {"config": {"counter-poll": mode}}}}
        if not config_rest(dut, rest_url = url, http_method=cli_type, json_data=config_data):
            st.error('Failed to {} PFC Watch-Dog counter poll'.format(mode))
            return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    if command:
        response = st.config(dut, command, type=cli_type, skip_error_check=skip_error)
        if any(error.lower() in response.lower() for error in errors):
            st.error("The response is: {}".format(response))
            return False
    return True


def show_pfc_wd_config(dut, ports=[], **kwargs):
    """
    To get PFC Watch-Dog configuration
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom)
    :param dut:
    :type dut:
    :param ports:
    :type list:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = cli_type if ports else 'click'
    ports = make_list(ports)
    if cli_type == 'click':
        command = "pfcwd show config"
        output = st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        output = list()
        for port in ports:
            intf_data = get_interface_number_from_name(port)
            command = "show qos interface {} {}".format(intf_data['type'], intf_data['number'])
            out = st.show(dut, command, type=cli_type)
            _ = out[0].update(interface=port) if out and isinstance(out, list) and isinstance(out[0], dict) else out
            output.extend(out)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        output = list()
        for port in ports:
            url = rest_urls['get_pfc_params'].format(port)
            out = get_rest(dut, rest_url = url)
            if (out and ('output' in out) and out.get('output')):
                out = _get_rest_pfc_params_config(out['output'])
                _ = out[0].update(interface=port) if out and isinstance(out, list) and isinstance(out[0], dict) else out
                output.extend(out)
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return output


def show_pfc_wd_stats(dut, **kwargs):
    """
    To get PFC Watch-Dog statistics
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom)
    :param dut:
    :type dut:
    :param ports:
    :type ports:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    ports = make_list(kwargs.get('ports', []))
    command = ''
    if cli_type == 'click':
        command = "pfcwd show stats"
        output = st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        if not ports:
            port = 'Eth all' if st.get_ifname_type(dut) in ['alias', 'std-ext'] else 'Ethernet all'
            command = "show qos interface {} priority-flow-control statistics queue".format(port)
            output = st.show(dut, command, type=cli_type)
        else:
            output = list()
            for port in ports:
                intf_data = get_interface_number_from_name(port)
                command = "show qos interface {} {} priority-flow-control statistics queue".format(intf_data['type'], intf_data['number'])
                output.extend(st.show(dut, command, type=cli_type))
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if not ports:
            url = rest_urls['get_pfc_all_counters']
            out = get_rest(dut, rest_url=url, timeout=120)
            if not (out and ('output' in out) and out.get('output')):
                st.error("No data found in output: {}".format(out))
                return False
            output = _get_rest_pfc_wd_stats_all(out['output'])
        else:
            output = list()
            for port in ports:
                url = rest_urls['get_pfcwd_counters'].format(port)
                out = get_rest(dut, rest_url=url, timeout=20)
                if not (out and ('output' in out) and out.get('output')):
                    st.error("No data found in output: {}".format(out))
                    return False
                output.extend(_get_rest_pfc_wd_stats(out['output'], port))
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return output


def show_asymmetric_pfc(dut, ports=[], cli_type=''):
    """
    To show asymmetric PFC configuration on ports
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :type dut:
    :param ports:
    :type list:
    :param cli_type:
    :type cli_type:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type = cli_type if ports else 'click'
    ports = make_list(ports)
    if cli_type == 'click':
        command = "pfc show asymmetric"
        output = st.show(dut, command, type=cli_type)
    elif cli_type == 'klish':
        output = list()
        for port in ports:
            intf_data = get_interface_number_from_name(port)
            command = "show qos interface {} {}".format(intf_data['type'], intf_data['number'])
            out = st.show(dut, command, type=cli_type)
            _ = out[0].update(interface=port) if out and isinstance(out, list) and isinstance(out[0], dict) else out
            output.extend(out)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        output = list()
        for port in ports:
            url = rest_urls['get_pfc_params'].format(port)
            out = get_rest(dut, rest_url = url)
            if (out and ('output' in out) and out.get('output')):
                out = _get_rest_pfc_params_config(out['output'])
                _ = out[0].update(interface=port) if out and isinstance(out, list) and isinstance(out[0], dict) else out
                output.extend(out)
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return output


def clear_pfc_counters(dut, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    cli_type = 'klish' if cli_type in ['rest-patch', 'rest-put'] else cli_type #Clear commands use RPC calls for those OC-YANG URLs won't be available
    if cli_type == 'click':
        command = "sonic-clear pfccounters"
        st.show(dut, command, skip_tmpl=True)
        st.wait(2, "Waiting to create PFC counter files")
        command = "ls /tmp/pfcstat-1000/"
        st.show(dut, command, skip_tmpl=True, skip_error_check=True)
    elif cli_type == 'klish':
        if not clear_interface_counters(dut, **kwargs):
            st.error("Failed to clear PFC counters")
            return False
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    return True


def show_pfc_counters(dut, **kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    ports = make_list(kwargs.get('ports', []))
    if cli_type == 'click':
        command = "show pfc counters"
        rv = st.show(dut, command, type=cli_type)
        if kwargs.get('debug', False):
            st.show(dut, "cat /tmp/pfcstat-1000/1000rx", skip_tmpl=True, skip_error_check=True)
            st.show(dut, "cat /tmp/pfcstat-1000/1000tx", skip_tmpl=True, skip_error_check=True)
    elif cli_type == 'klish':
        if not ports:
            port = 'Eth all' if st.get_ifname_type(dut) in ['alias', 'std-ext'] else 'Ethernet all'
            command = "show qos interface {} priority-flow-control statistics".format(port)
            rv = st.show(dut, command, type=cli_type)
        else:
            rv = list()
            for port in ports:
                intf_data = get_interface_number_from_name(port)
                command = "show qos interface {} {} priority-flow-control statistics".format(intf_data['type'], intf_data['number'])
                rv.extend(st.show(dut, command, type=cli_type))
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if not ports:
            url = rest_urls['get_pfc_all_counters']
            out = get_rest(dut, rest_url=url, timeout=120)
            if not (('output' in out) and out.get('output')):
                st.error("No data found in output: {}".format(out))
                return False
            rv = _get_rest_pfc_counters_all(out['output'])
        else:
            rv = list()
            for port in ports:
                url = rest_urls['get_pfc_pause_counters'].format(port)
                out = get_rest(dut, rest_url=url, timeout=120)
                if not (('output' in out) and out.get('output')):
                    st.error("No data found in output: {}".format(out))
                    return False
                rv.extend(_get_rest_pfc_counters(out['output'], port))
    else:
        st.error("Unsupported CLI TYPE {}".format(cli_type))
        return False
    output = [{k: v.replace('received', 'Port Rx').replace('transmitted', 'Port Tx').replace(',', '') for k, v in each.items()} for each in rv]
    return output


def get_pfc_counters(dut,interface,mode,*argv):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface:
    :param mode:
    :param argv: 'pfc0','pfc1','pfc2','pfc3','pfc4','pfc5','pfc6','pfc7'
    :return:
    """
    output = show_pfc_counters(dut)
    port_mode = 'Port Tx'
    if mode.lower() == 'rx':
        port_mode = 'Port Rx'
    entries = filter_and_select(output,argv,{'port':interface,'port_mode':port_mode})
    return entries


def get_pfc_counters_all(dut, interface, mode='tx'):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface:
    :param mode:
    :param kwargs:
    :return:
    """

    output = show_pfc_counters(dut)
    port_mode = 'Port Tx'
    if mode.lower() == 'rx':
        port_mode = 'Port Rx'
    match = {'port':interface,'port_mode':port_mode}
    entries = filter_and_select(output, None, match)
    if not entries:
        st.log("No queue couters found on {} for {} {}".format(dut, interface, mode))
        return (False,0)
    new_entry = {}
    for i in entries[0]:
        new_entry[i]=entries[0][i].replace(",","")
    return (True,new_entry)

def verify_pfc_counters(dut,interface,mode='tx',**kwargs):
    """
    Author: Prudvi Mangadu (prudvi.mangadu@broadcom.com)
    :param dut:
    :param interface:
    :param mode:
    :param kwargs:
    :return:
    """

    output = show_pfc_counters(dut)
    port_mode = 'Port Tx'
    if mode.lower() == 'rx':
        port_mode = 'Port Rx'

    for each in kwargs.keys():
        match = {'port':interface,'port_mode':port_mode,each:kwargs[each]}
        entries = filter_and_select(output, None, match)
        if not entries:
            st.log("{} and {} is not match ".format(each, kwargs[each]))
            return False
    return True


def config_pfc_buffer_prameters(dut, hwsku, ports_dict, **kwargs):
    """
    Autor: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    To configure the platform specific buffer constants
    :param hwsku:
    :type hwsku:
    :param dut:
    :type dut:
    :param ports_dict:
    :type ports_dict:
    """
    st.banner("Applying the PFC buffer parameters on dut {} platform {} port dict {}".format(dut, hwsku, ports_dict))
    constants = st.get_datastore(dut, "constants")
    ports_show = interface_status_show(dut, list(ports_dict.keys()))
    port_speed = dict()
    core_buffer_config = kwargs.get('core_buffer_config', False)
    apply_buffer_config = kwargs.get('apply_buffer_config', True)
    for port in ports_dict.keys():
        port_speed[port] = filter_and_select(ports_show, ['speed'], {'interface': port})[0]['speed'].replace('G', '000')
    native_ports_map_dict = {port: convert_intf_name_to_component(dut, intf_list=[port], component='applications') for port in ports_dict.keys()}
    #native_ports_map_dict = {port:st.get_other_names(dut, [port])[0] if '/' in port else port for port in ports_dict.keys()}
    retval = dict()
    update_retval = lambda entries: {retval.update(entry) for entry in entries}
    if hwsku.lower() in constants['TH_PLATFORMS']:
        if core_buffer_config:
            buffer_pool = {"BUFFER_POOL": {"egress_lossless_pool": {"mode": "static", "size": "12766208", "type": "egress"},
                                           "egress_lossy_pool": {"mode": "dynamic", "size": "7326924", "type": "egress"},
                                           "ingress_lossless_pool": {"mode": "dynamic", "size": "12766208", "type": "ingress", "xoff": "4625920"}}}
            buffer_profile = {"BUFFER_PROFILE": {"egress_lossless_profile": {"pool": "[BUFFER_POOL|egress_lossless_pool]", "size": "0", "static_th": "12766208"},                                     "egress_lossy_profile": {"dynamic_th": "3", "pool": "[BUFFER_POOL|egress_lossless_pool]", "size": "1518"},
                                                 "ingress_lossy_profile": {"dynamic_th": "3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "0"},
                                                 "pg_lossless_10000_300m_profile": {"dynamic_th": "-3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_25000_300m_profile": {"dynamic_th": "-3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_40000_300m_profile": {"dynamic_th": "-3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_100000_300m_profile": {"dynamic_th": "-3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"}}}
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "300m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'100000' : 'pg_lossless_100000_300m_profile', '40000' : 'pg_lossless_40000_300m_profile', '25000' : 'pg_lossless_25000_300m_profile', '10000' : 'pg_lossless_10000_300m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "[BUFFER_PROFILE|{}]".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)

    elif hwsku.lower() in constants['TH2_PLATFORMS']:
        if core_buffer_config:
            buffer_pool = {"BUFFER_POOL": {"egress_lossless_pool": {"mode": "static", "size": "12766208", "type": "egress"},
                                       "egress_lossy_pool": {"mode": "dynamic", "size": "7326924", "type": "egress"},
                                       "ingress_lossless_pool": {"mode": "dynamic", "size": "12766208", "type": "ingress", "xoff": "4625920"}}}
            buffer_profile = {"BUFFER_PROFILE": {"egress_lossless_profile": {"pool": "[BUFFER_POOL|egress_lossless_pool]", "size": "0", "static_th": "12766208"},                                     "egress_lossy_profile": {"dynamic_th": "3", "pool": "[BUFFER_POOL|egress_lossless_pool]", "size": "1518"},
                                                 "ingress_lossy_profile": {"dynamic_th": "3","pool": "[BUFFER_POOL|ingress_lossless_pool]","size": "0"},
                                                 "pg_lossless_10000_300m_profile": {"dynamic_th": "-3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_25000_300m_profile": {"dynamic_th": "-3","pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_40000_300m_profile": {"dynamic_th": "-3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_100000_300m_profile": {"dynamic_th": "-3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"}}}
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "300m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'10000' : 'pg_lossless_10000_300m_profile', '25000' : 'pg_lossless_25000_300m_profile', '40000' : 'pg_lossless_40000_300m_profile', '100000' : 'pg_lossless_100000_300m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "[BUFFER_PROFILE|{}]".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)
    elif hwsku.lower() in constants['TD4_PLATFORMS']:
        if core_buffer_config:
            buffer_pool = {"BUFFER_POOL": {"egress_lossless_pool": {"mode": "static", "size": "67108864", "type": "egress"},
                                       "ingress_lossless_pool":    {"mode": "dynamic", "size": "51380224", "type": "ingress", "xoff": "5728640"}}}
            buffer_profile = {"BUFFER_PROFILE": {"egress_lossless_profile": {"pool": "[BUFFER_POOL|egress_lossless_pool]", "size": "0", "static_th": "67108864"},
                                                 "egress_lossy_profile": {"dynamic_th": "3", "pool": "[BUFFER_POOL|egress_lossless_pool]", "size": "0"},
                                                 "ingress_lossy_profile": {"dynamic_th": "3","pool": "[BUFFER_POOL|ingress_lossless_pool]","size": "0"},
                                                 "pg_lossless_10000_300m_profile": {"dynamic_th": "-1", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "1270", "xoff": "4070688", "xon": "2540", "xon_offset": "4070148"},
                                                 "pg_lossless_25000_300m_profile": {"dynamic_th": "-1","pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "1270", "xoff": "4070688", "xon": "2540", "xon_offset": "4070148"},
                                                 "pg_lossless_40000_300m_profile": {"dynamic_th": "-1", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "1270", "xoff": "4070688", "xon": "2540", "xon_offset": "4070148"},
                                                 "pg_lossless_400000_300m_profile": {"dynamic_th": "-1", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "1270", "xoff": "4070688", "xon": "2540", "xon_offset": "4070148"},
                                                 "pg_lossless_100000_300m_profile": {"dynamic_th": "-1", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "1270", "xoff": "4070688", "xon": "2540", "xon_offset": "4070148"}}}
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "300m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'10000' : 'pg_lossless_10000_300m_profile', '25000' : 'pg_lossless_25000_300m_profile', '40000' : 'pg_lossless_40000_300m_profile', '100000' : 'pg_lossless_100000_300m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "[BUFFER_PROFILE|{}]".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)

    elif hwsku.lower() in constants['TH3_PLATFORMS']:
        if core_buffer_config:
            buffer_pool = {"BUFFER_POOL": {"egress_lossy_pool": {"mode": "dynamic", "size": "67108864", "type": "egress"},
                                           "ingress_lossless_pool": {"mode": "dynamic", "size": "59001152", "type": "ingress", "xoff": "7428992"}}}
            buffer_profile = {"BUFFER_PROFILE": {"egress_lossless_profile": {"dynamic_th": "3", "pool": "[BUFFER_POOL|egress_lossy_pool]", "size": "0"},
                                                 "egress_lossy_profile": {"dynamic_th": "3", "pool": "[BUFFER_POOL|egress_lossy_pool]", "size": "0"},
                                                 "ingress_lossy_profile": {"pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "0", "static_th": "67108864"},
                                                 "pg_lossless_10000_40m_profile": {"dynamic_th": "-2", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "1270", "xoff": "190500", "xon": "0", "xon_offset": "2540"},
                                                 "pg_lossless_50000_40m_profile": {"dynamic_th": "-2", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "1270", "xoff": "190500", "xon": "0", "xon_offset": "2540"},
                                                 "pg_lossless_100000_40m_profile": {"dynamic_th": "-2", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "1270", "xoff": "190500", "xon": "0", "xon_offset": "2540"},
                                                 "pg_lossless_200000_40m_profile": {"dynamic_th": "-2", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "1270", "xoff": "190500", "xon": "0", "xon_offset": "2540"},
                                                 "pg_lossless_400000_40m_profile": {"dynamic_th": "-2", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "1270","xoff": "190500", "xon": "0", "xon_offset": "2540"}}}
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "40m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'400000' : 'pg_lossless_400000_40m_profile', '200000' : 'pg_lossless_200000_40m_profile', '100000' : 'pg_lossless_100000_40m_profile', '50000': 'pg_lossless_50000_40m_profile', '10000' : 'pg_lossless_10000_40m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "[BUFFER_PROFILE|{}]".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)

    elif hwsku.lower() in constants['TD2_PLATFORMS']:
        if core_buffer_config:
            buffer_pool = {"BUFFER_POOL": {"egress_lossless_pool": {"mode": "static", "size": "12766208", "type": "egress"},
                                           "egress_lossy_pool": {"mode": "dynamic", "size": "7326924", "type": "egress"},
                                           "ingress_lossless_pool": {"mode": "dynamic", "size": "12766208", "type": "ingress"}}}
            buffer_profile = {"BUFFER_PROFILE": {"egress_lossless_profile": {"pool": "[BUFFER_POOL|egress_lossless_pool]", "size": "0", "static_th": "12766208"},                                     "egress_lossy_profile": {"dynamic_th": "3", "pool": "[BUFFER_POOL|egress_lossless_pool]", "size": "1518"},
                                                 "ingress_lossy_profile": {"dynamic_th": "3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "0"},
                                                 "pg_lossless_1000_300m_profile": {"dynamic_th": "-3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_10000_300m_profile": {"dynamic_th": "-3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"},
                                                 "pg_lossless_40000_300m_profile": {"dynamic_th": "-3", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "56368", "xoff": "55120", "xon": "18432", "xon_offset": "2496"}}}
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "300m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'10000' : 'pg_lossless_10000_300m_profile', '40000' : 'pg_lossless_40000_300m_profile', '1000' : 'pg_lossless_1000_300m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "[BUFFER_PROFILE|{}]".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)

    elif hwsku.lower() in constants['TD3_PLATFORMS']:
        if core_buffer_config:
            buffer_pool =  {
                "BUFFER_POOL": {
                    "ingress_lossless_pool": {
                        "size": "32157184",
                        "type": "ingress",
                        "mode": "dynamic",
                        "xoff": "2621440"
                    },

                    "egress_lossy_pool": {
                        "size": "24320512",
                        "type": "egress",
                        "mode": "dynamic"
                    },
                    "egress_lossless_pool": {
                        "size": "31617024",
                        "type": "egress",
                        "mode": "static"
                    }
                }
            }
            buffer_profile =  {
                "BUFFER_PROFILE": {
                    "ingress_lossy_profile": {
                        "pool":"[BUFFER_POOL|ingress_lossless_pool]",
                        "size":"0",
                        "static_th":"32566016"
                    },
                    "egress_lossless_profile": {
                        "pool":"[BUFFER_POOL|egress_lossless_pool]",
                        "size":"0",
                        "static_th":"32194560"
                    },
                    "egress_lossy_profile": {
                        "pool":"[BUFFER_POOL|egress_lossy_pool]",
                        "size":"0",
                        "dynamic_th":"3"
                    },
                    "pg_lossless_10000_300m_profile": {
                        "dynamic_th": "0",
                        "pool": "[BUFFER_POOL|ingress_lossless_pool]",
                        "size": "9216",
                        "xoff": "57088",
                        "xon": "9216",
                        "xon_offset": "9216"
                    },
                    "pg_lossless_25000_300m_profile": {
                        "dynamic_th": "0",
                        "pool": "[BUFFER_POOL|ingress_lossless_pool]",
                        "size": "9216",
                        "xoff": "92672",
                        "xon": "9216",
                        "xon_offset": "9216"
                    },
                    "pg_lossless_40000_300m_profile": {
                        "dynamic_th": "0",
                        "pool": "[BUFFER_POOL|ingress_lossless_pool]",
                        "size": "9216",
                        "xoff": "121344",
                        "xon": "9216",
                        "xon_offset": "9216"
                    },
                    "pg_lossless_100000_300m_profile": {
                        "dynamic_th": "0",
                        "pool": "[BUFFER_POOL|ingress_lossless_pool]",
                        "size": "9216",
                        "xoff": "272640",
                        "xon": "9216",
                        "xon_offset": "9216"
                    }
                }
            }


            if hwsku.lower() in ['quanta-ix8a-bwde-56x', 'accton-as4630-54pe']:
                buffer_profile['BUFFER_PROFILE'].update(pg_lossless_1000_300m_profile={"dynamic_th": "0", "pool": "[BUFFER_POOL|ingress_lossless_pool]", "size": "9216", "xoff": "50176", "xon": "9216", "xon_offset": "9216"})
            cable_length_config = {"CABLE_LENGTH": {"AZURE": {native_ports_map_dict[port]: "300m" for port in ports_dict.keys()}}}
            update_retval([buffer_pool, buffer_profile, cable_length_config])
        if apply_buffer_config:
            ingress_profile_mapping = {'100000' : 'pg_lossless_100000_300m_profile', '40000' : 'pg_lossless_40000_300m_profile', '25000' : 'pg_lossless_25000_300m_profile', '10000' : 'pg_lossless_10000_300m_profile', 'lossy_profile': 'ingress_lossy_profile'}
            if hwsku.lower() in ['quanta-ix8a-bwde-56x', 'accton-as4630-54pe']:
                ingress_profile_mapping.update({'1000': 'pg_lossless_1000_300m_profile'})
            egress_profile_mapping = {'lossy_profile' : 'egress_lossy_profile', 'lossless_profile' : 'egress_lossless_profile'}
            buffer_pg = dict()
            buffer_queue = dict()
            get_profile = lambda profile: {"profile": "[BUFFER_PROFILE|{}]".format(profile)}
            for port, queue_info in ports_dict.items():
                native_port = native_ports_map_dict[port]
                for queue_type, queues in queue_info.items():
                    buffer_pg.update({"{}|{}".format(native_port, queue):get_profile(ingress_profile_mapping[port_speed[port]] if queue_type == 'lossless_queues' else ingress_profile_mapping['lossy_profile']) for queue in queues})
                    buffer_queue.update({"{}|{}".format(native_port, queue):get_profile(egress_profile_mapping['lossless_profile'] if queue_type == 'lossless_queues' else egress_profile_mapping['lossy_profile']) for queue in queues})
            buffer_pg = {"BUFFER_PG":buffer_pg}
            buffer_queue = {"BUFFER_QUEUE":buffer_queue}
            update_retval([buffer_pg, buffer_queue])
        st.debug(retval)

    else:
        st.error("Invalid platform")
        return False
    if retval:
        final_data = json.dumps(retval)
        st.apply_json2(dut, final_data)
    return True


def _get_rest_pfc_wd_stats(data, port):
    """
    To get processed output from REST PFC watchdog statistics per port
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param : data
    :return:
    """
    retval = list()
    if data.get("openconfig-qos:pfc-queue") and data["openconfig-qos:pfc-queue"].get("pfc-queue") and isinstance(data["openconfig-qos:pfc-queue"]["pfc-queue"], list):
        entries = data["openconfig-qos:pfc-queue"]["pfc-queue"]
        for entry in entries:
            temp = dict()
            if 'queue' in entry and entry.get('state') and entry['state'].get('statistics'):
                stats = entry['state']['statistics']
                temp['port'] = port
                temp['status'] = 'N/A'
                temp['queue'] = str(entry['queue'])
                if 'rx-drop' in stats:
                    temp['rx_drop'] = str(stats['rx-drop'])
                if 'rx-drop-last' in stats:
                    temp['rx_last_drop'] = str(stats['rx-drop-last'])
                if 'rx-ok' in stats:
                    temp['rx_ok'] = str(stats['rx-ok'])
                if 'rx-ok-last' in stats:
                    temp['rx_last_ok'] = str(stats['rx-ok-last'])
                if 'storm-detected' in stats:
                    temp['storm_detect'] = str(stats['storm-detected'])
                if 'storm-restored' in stats:
                    temp['storm_restore'] = str(stats['storm-restored'])
                if 'tx-drop' in stats:
                    temp['tx_drop'] = str(stats['tx-drop'])
                if 'tx-drop-last' in stats:
                    temp['tx_last_drop'] = str(stats['tx-drop-last'])
                if 'tx-ok' in stats:
                    temp['tx_ok'] = str(stats['tx-ok'])
                if 'tx-ok-last' in stats:
                    temp['tx_last_ok'] = str(stats['tx-ok-last'])
                retval.append(temp)
    st.debug(retval)
    return retval


def _get_rest_pfc_wd_stats_all(data):
    """
    To get processed output from REST PFC watchdog statistics for all ports
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param : data
    :return:
    """
    retval = list()
    if "openconfig-qos:interface" in data and data.get("openconfig-qos:interface") and isinstance(data["openconfig-qos:interface"], list):
        entries = data["openconfig-qos:interface"]
        for entry in entries:
            if "interface-id" in entry and entry.get("pfc") and entry["pfc"].get("pfc-queue") and entry["pfc"]["pfc-queue"].get("pfc-queue") and isinstance(entry["pfc"]["pfc-queue"]["pfc-queue"], list):
                pfcwd_stats = entry["pfc"]["pfc-queue"]["pfc-queue"]
                for pfcwd_stat in pfcwd_stats:
                    temp = dict()
                    if 'queue' in pfcwd_stat and pfcwd_stat.get('state') and pfcwd_stat['state'].get('statistics'):
                        stats = pfcwd_stat['state']['statistics']
                        temp['port'] = entry['interface-id']
                        temp['status'] = 'N/A'
                        temp['queue'] = str(pfcwd_stat['queue'])
                        if 'rx-drop' in stats:
                            temp['rx_drop'] = str(stats['rx-drop'])
                        if 'rx-drop-last' in stats:
                            temp['rx_last_drop'] = str(stats['rx-drop-last'])
                        if 'rx-ok' in stats:
                            temp['rx_ok'] = str(stats['rx-ok'])
                        if 'rx-ok-last' in stats:
                            temp['rx_last_ok'] = str(stats['rx-ok-last'])
                        if 'storm-detected' in stats:
                            temp['storm_detect'] = str(stats['storm-detected'])
                        if 'storm-restored' in stats:
                            temp['storm_restore'] = str(stats['storm-restored'])
                        if 'tx-drop' in stats:
                            temp['tx_drop'] = str(stats['tx-drop'])
                        if 'tx-drop-last' in stats:
                            temp['tx_last_drop'] = str(stats['tx-drop-last'])
                        if 'tx-ok' in stats:
                            temp['tx_ok'] = str(stats['tx-ok'])
                        if 'tx-ok-last' in stats:
                            temp['tx_last_ok'] = str(stats['tx-ok-last'])
                        retval.append(temp)
    st.debug(retval)
    return retval


def _get_rest_pfc_counters(data, port):
    """
    To get processed output from REST PFC statistics per port
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param : data
    :return:
    """
    rx_entry = {'port': port, 'port_mode': 'received'}
    tx_entry = {'port': port, 'port_mode': 'transmitted'}
    if "openconfig-qos:pfc-priority" in data and data["openconfig-qos:pfc-priority"] and isinstance(data["openconfig-qos:pfc-priority"], list):
        entries = data["openconfig-qos:pfc-priority"]
        for entry in entries:
            if entry.get('state') and entry['state'].get('statistics') and 'dot1p' in entry['state']:
                stats = entry['state']['statistics']
                if 'pause-frames-rx' in stats:
                    rx_entry['pfc{}'.format(entry['state']['dot1p'])] = str(stats['pause-frames-rx'])
                if 'pause-frames-tx' in stats:
                    tx_entry['pfc{}'.format(entry['state']['dot1p'])] = str(stats['pause-frames-tx'])
    st.debug([rx_entry, tx_entry])
    return [rx_entry, tx_entry]


def _get_rest_pfc_counters_all(data):
    """
    To get processed output from REST PFC statistics for all ports
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param : data
    :return:
    """
    retval = list()
    if "openconfig-qos:interface" in data and data.get("openconfig-qos:interface") and isinstance(data["openconfig-qos:interface"], list):
        entries = data["openconfig-qos:interface"]
        for entry in entries:
            if "interface-id" in entry and entry.get("pfc") and entry["pfc"].get("pfc-priorities") and entry["pfc"]["pfc-priorities"].get("pfc-priority") and isinstance(entry["pfc"]["pfc-priorities"]["pfc-priority"], list):
                pfc_stats = entry["pfc"]["pfc-priorities"]["pfc-priority"]
                rx_entry = {'port': entry["interface-id"], 'port_mode': 'received'}
                tx_entry = {'port': entry["interface-id"], 'port_mode': 'transmitted'}
                for pfc_stat in pfc_stats:
                    if pfc_stat.get('state') and pfc_stat['state'].get('statistics') and 'dot1p' in pfc_stat['state']:
                        stats = pfc_stat['state']['statistics']
                        if 'pause-frames-rx' in stats:
                            rx_entry['pfc{}'.format(pfc_stat['state']['dot1p'])] = str(stats['pause-frames-rx'])
                        if 'pause-frames-tx' in stats:
                            tx_entry['pfc{}'.format(pfc_stat['state']['dot1p'])] = str(stats['pause-frames-tx'])
                retval.extend([rx_entry, tx_entry])
    st.debug(retval)
    return retval


def _get_rest_pfc_params_config(data):
    """
    To get PFC parameters configured on port from REST output
    Author: Jagadish Chatrasi (jagadish.chatrasi@broadcom)
    :param data:
    :type data:
    """
    retval = dict()
    if "pfc" in data and "state" in data["pfc"] and "asymmetric" in data["pfc"]["state"] and data["pfc"]["state"]["asymmetric"]:
        retval['pfc_asymmetric'] = "on"
    else:
        retval['pfc_asymmetric'] = "off"
    if "pfc" in data and "pfc-priorities" in data["pfc"] and "pfc-priority" in data["pfc"]["pfc-priorities"]:
        priority_entries = data["pfc"]["pfc-priorities"]["pfc-priority"]
        if isinstance(priority_entries, list):
            pfc_lossless_priorities = [str(priority_entry['state']['dot1p']) for priority_entry in priority_entries if 'state' in priority_entry and 'dot1p' in priority_entry['state'] and 'enable' in priority_entry['state'] and priority_entry['state']['enable']]
            retval['pfc_priority'] = ','.join(pfc_lossless_priorities) if pfc_lossless_priorities else ''
    else:
        retval['pfc_priority'] = ''
    if "pfc" in data and "watchdog" in data["pfc"] and "state" in data["pfc"]["watchdog"]:
        wathdog_data = data["pfc"]["watchdog"]["state"]
        retval['action'] = wathdog_data["action"].lower() if "action" in wathdog_data else "N/A"
        retval['detectiontime'] = str(wathdog_data["detection-time"]) if "detection-time" in wathdog_data else "0"
        retval['restorationtime'] = str(wathdog_data["restoration-time"]) if "restoration-time" in wathdog_data else "0"
    else:
        retval['action'], retval['detectiontime'], retval['restorationtime'] = "N/A", "0", "0"
    st.debug([retval])
    return [retval]


