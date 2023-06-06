# Author: Mohammed Abdul Raheem Ali
# Email: mohammed.raheem-ali@broadcom.com
# Purpose: API to Configure and Verify Forward Drop Counters.

from spytest import st
from utilities.common import filter_and_select
from utilities.utils import make_list, get_supported_ui_type_list
from apis.system.rest import delete_rest, config_rest, get_rest

def verify_dropcounters(dut, **kwargs):
    '''
    Purpose: To Verify Drop Counter Config/Capabilities
    :param dut:
    :param kwargs:
    :return:
    '''
    st.banner("Verifying Drop Counter Configuration")
    ret_val = True
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type = force_cli_type_to_klish(cli_type)
    command = ''
    cmd_type = kwargs.get("cmd_type", '')
    sub_cmd = kwargs.get('sub_cmd', '')
    interface = kwargs.get("interface", '')
    kwargs.pop('cmd_type', None)
    kwargs.pop('sub_cmd', None)
    if cli_type == 'klish':
        if cmd_type.lower() == 'dropcounters':
            command = 'show interface dropcounters {}'.format(interface)
        elif cmd_type.lower() == 'configuration':
            if sub_cmd.lower() == 'detail':
                command = 'show dropcounters configuration detail'
            else:
                command = 'show dropcounters configuration'
        else:
            command = 'show dropcounters capabilities'
        output = st.show(dut, command, type=cli_type, skip_tmpl=False)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if cmd_type == 'configuration' and sub_cmd.lower() == 'detail':
            url = rest_urls['dropcounters_config_detail']
            output_detail = get_rest(dut, http_method=cli_type, rest_url=url)
            try:
                response = output_detail["output"]["sonic-debugcounter:DEBUG_COUNTER_LIST"]
                output = []
                for item in response:
                    temp = {}
                    temp['status'] = item['status']
                    if 'alias' in item:
                        temp['alias'] = item['alias']
                    temp['type'] = item['type']
                    temp['description'] = item['desc']
                    temp['counter'] = item['name']
                    temp['group'] = item['group']
                    if 'mirror' in item:
                        temp['mirror'] = item['mirror']
                    temp['reason_list'] = ','.join(item['reasons'])
                    output.append(temp)
            except Exception as e:
                st.error("Exception is : {}".format(e))
                return False
        elif cmd_type == 'dropcounters':
            url = rest_urls['dropcounters_per_interface']
            payload = {"sonic-counters:input": {"iface": interface}}
            output = config_rest(dut, http_method='post', rest_url=url, json_data=payload, get_response=True)
            try:
                response = output["output"]["sonic-counters:output"]["interfaces"]['interface']
                output = []
                for key, value in response.items():
                    if 'state' in value:
                        temp = {}
                        temp['iface'] = value['name']
                        temp['tx_err'] = str(value['state']['counters']['out-errors'])
                        temp['tx_drop'] = str(value['state']['counters']['out-discards'])
                        temp['rx_err'] = str(value['state']['counters']['in-errors'])
                        temp['rx_drop'] = str(value['state']['counters']['in-discards'])
                        temp['counter'] = temp['counter_1'] = temp['counter_2'] = '0'
                        check_flag = True
                        success = False
                        for i in range(0, 8):
                            counter = value['state']['counters']['counter{}-name'.format(i)]
                            if counter != '' and check_flag:
                                temp['counter'] = str(value['state']['counters']["counter{}-value".format(i)])
                                check_flag = False
                            elif temp['counter'] != 0 and check_flag is False and counter != '' and success is False:
                                temp['counter_1'] = str(value['state']['counters']["counter{}-value".format(i)])
                                success = True
                            elif temp['counter'] != 0 and temp['counter_1'] != 0 and success and counter != '':
                                temp['counter_2'] = str(value['state']['counters']["counter{}-value".format(i)])
                                success = check_flag = False
                        temp['state'] = value['state']['oper-status'].replace('UP', 'U').replace('DOWN', 'D')
                        output.append(temp)
                        st.debug(output)
            except Exception as e:
                st.error("The Exception is: {}".format(e))
                return False
        else:
            url = rest_urls['dropcounters_capabilities']
            output = get_rest(dut, http_method=cli_type, rest_url=url)
            try:
                response = output['output']['sonic-debugcounter:DEBUG_COUNTER_CAPABILITIES']['DEBUG_COUNTER_CAPABILITIES_LIST'][0]
                output = []
                temp = {}
                temp['port_ingress_drops'] = str(response['count'])
                temp['port_ingress_drops_reason_list'] = response['reasons'].strip('][').split(',')
                temp['port_mirror_supported_ingress_drops'] = response['mirror_reasons']
                output.append(temp)
                st.debug(output)
            except Exception as e:
                st.error("Exception is : {}".format(e))
                return False

    if len(output) == 0:
        st.error("Output is Empty")
        return False

    if 'return_output' in kwargs:
        return output

    for key in kwargs:
        if type(kwargs[key]) is list:
            kwargs[key] = list(kwargs[key])
        else:
            kwargs[key] = [kwargs[key]]

    #convert kwargs into list of dictionary
    input_dict_list = []
    for i in range(len(kwargs[list(kwargs.keys())[0]])):
        temp_dict = {}
        for key in kwargs.keys():
            if isinstance(kwargs[key][i], list):
                temp_dict[key] = kwargs[key][i][0]
            else:
                temp_dict[key] = kwargs[key][i]
        input_dict_list.append(temp_dict)
    for input_dict in input_dict_list:
        if cmd_type in ['capabilities', 'configuration']:
            output = get_processed_output(output, type=cmd_type)
        entries = filter_and_select(output, None, match=input_dict)
        if not entries:
            st.error("DUT {} -> Match Not Found {}".format(dut, input_dict))
            ret_val = False

    return ret_val

def config_dropcounter(dut, dropcounter_name, **kwargs):
    '''
    Purpose: To configure Dropcounter
    :param dut:
    :param kwargs:
    :return:
    '''
    cli_type = st.get_ui_type(dut, **kwargs)
    ### Rest URI is sonic-yang implementation forcing to klish
    cli_type = force_cli_type_to_klish(cli_type)
    dropcounter_reason_list = kwargs.get("dropcounter_reason_list", None)
    dropcounter_type = kwargs.get("dropcounter_type", None)
    dropcounter_group = kwargs.get("dropcounter_group", None)
    dropcounter_description = kwargs.get("dropcounter_description", None)
    dropcounter_alias = kwargs.get("dropcounter_alias", None)
    mirror_session = kwargs.get("mirror_session", None)
    enable = kwargs.get("enable", None)
    config = kwargs.get('config', 'yes')
    skip_error_check = kwargs.get('skip_error_check', False)
    delete_dropcounter = kwargs.get('delete_dropcounter', False)
    st.banner("Configuring Drop Counter {} on {}".format(dropcounter_name, dut))
    if cli_type == 'klish':
        command = []
        command.append('dropcounters {}'.format(dropcounter_name))
        if dropcounter_description:
            if config == 'yes':
                command.append('description \"{}\"'.format(dropcounter_description))
            else:
                command.append('no description \"{}\"'.format(dropcounter_description))
        if dropcounter_group:
            if config == 'yes':
                command.append('group \"{}\"'.format(dropcounter_group))
            else:
                command.append('no group')
        if dropcounter_alias:
            if config == 'yes':
                command.append('alias \"{}\"'.format(dropcounter_alias))
            else:
                command.append('no alias')
        if dropcounter_reason_list:
            for reason in make_list(dropcounter_reason_list):
                if config == 'yes':
                    command.append('add-reason {}'.format(reason))
                else:
                    command.append('delete-reason {}'.format(reason))
        if dropcounter_type:
            if config == 'yes':
                command.append('type {}'.format(dropcounter_type))
            else:
                command.append('no type')
        if mirror_session:
            if config == 'yes':
                command.append('mirror {}'.format(mirror_session))
        if enable:
            if config == 'yes':
                command.append('enable')
            else:
                command.append('no enable')
        if mirror_session:
            if config != 'yes':
                command.append('no mirror')
        command.append('exit')
        if delete_dropcounter:
            command.append('no dropcounters {}'.format(dropcounter_name))

        result = st.config(dut, command, type=cli_type, skip_error_check=skip_error_check)
        if '%Error' in result:
            return False
        return True
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if config == 'yes':
            url = rest_urls['config_dropcounter']
            temp = {}
            temp.update({"sonic-debugcounter:DEBUG_COUNTER":{"DEBUG_COUNTER_LIST": [{"name": dropcounter_name}]}})
            if dropcounter_description:
                temp['sonic-debugcounter:DEBUG_COUNTER']['DEBUG_COUNTER_LIST'][0].update({"desc": dropcounter_description})
            if dropcounter_group:
                temp['sonic-debugcounter:DEBUG_COUNTER']['DEBUG_COUNTER_LIST'][0].update({"group": dropcounter_group})
            if dropcounter_alias:
                temp['sonic-debugcounter:DEBUG_COUNTER']['DEBUG_COUNTER_LIST'][0].update({"alias": dropcounter_alias})
            if dropcounter_type:
                temp['sonic-debugcounter:DEBUG_COUNTER']['DEBUG_COUNTER_LIST'][0].update({"type": dropcounter_type})
            if mirror_session:
                temp['sonic-debugcounter:DEBUG_COUNTER']['DEBUG_COUNTER_LIST'][0].update({"mirror": mirror_session})
            if enable:
                temp['sonic-debugcounter:DEBUG_COUNTER']['DEBUG_COUNTER_LIST'][0].update({"status": "enable"})
            if dropcounter_reason_list:
                for reason in make_list(dropcounter_reason_list):
                    temp['sonic-debugcounter:DEBUG_COUNTER']['DEBUG_COUNTER_LIST'][0].update({"reasons": [reason]})
            if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=temp):
                st.error("Failed to Configure Drop Counter")
                return False
            return True
        else:
            if dropcounter_description:
                url = rest_urls['delete_description'].format(name=dropcounter_name)
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to Delete")
                    return False
            if dropcounter_group:
                url = rest_urls['delete_group'].format(name=dropcounter_name)
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to Delete")
                    return False
            if dropcounter_alias:
                url = rest_urls['delete_alias'].format(name=dropcounter_name)
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to Delete")
                    return False
            if dropcounter_type:
                url = rest_urls['delete_type'].format(name=dropcounter_name)
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to Delete")
                    return False
            if enable:
                payload = {"sonic-debugcounter:status": "disable"}
                url = rest_urls['delete_status'].format(name=dropcounter_name)
                if not config_rest(dut, rest_url=url, http_method=cli_type, json_data=payload):
                    st.error("Failed to Delete")
                    return False
            if mirror_session:
                url = rest_urls['delete_mirror'].format(name=dropcounter_name)
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to Delete")
                    return False
            if dropcounter_reason_list:
                for reason in make_list(dropcounter_reason_list):
                    url = rest_urls['delete_reason'].format(name=dropcounter_name, reasons=reason)
                    if not delete_rest(dut, rest_url=url):
                        st.error("Failed to Delete")
                        return False
            if delete_dropcounter:
                url = rest_urls['delete_dropcounter'].format(name=dropcounter_name)
                if not delete_rest(dut, rest_url=url):
                    st.error("Failed to Delete")
                    return False
            return True

def get_processed_output(output, type=None):
    if type == 'capabilities':
        retval = []
        if output and isinstance(output, list) and isinstance(output[0], dict):
            for reason_list in make_list(output[0]['port_ingress_drops_reason_list']):
                temp = {}
                temp['port_mirror_supported_ingress_drops'] = output[0]['port_mirror_supported_ingress_drops']
                temp['port_ingress_drops_reason_list'] = reason_list
                temp['port_ingress_drops'] = output[0]['port_ingress_drops']
                if 'switch_egress_drops' in output[0]:
                    temp['switch_egress_drops'] = output[0]['switch_egress_drops']
                retval.append(temp)
            return retval
        else:
            return output
    else:
        retval = []
        for key in output:
            i = 0
            temp = {}
            if key['reason_list']:
                result = key['reason_list'].split(',')
            for _ in range(len(result)):
                temp['reason_list'] = result[i]
                i += 1
                temp1 = temp.copy()
                temp1['status'] = key['status']
                temp1['group'] = key['group']
                if 'mirror' in key:
                    temp1['mirror'] = key['mirror']
                temp1['type'] = key['type']
                if 'alias' in key:
                    temp1['alias'] = key['alias']
                temp1['description'] = key['description']
                temp1['counter'] = key['counter']
                retval.append(temp1)
            return retval


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type
