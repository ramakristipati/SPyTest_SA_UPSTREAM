from spytest import st
from utilities.common import filter_and_select, make_list
from utilities.utils import get_interface_number_from_name, segregate_intf_list_type, is_a_single_intf, get_supported_ui_type_list
from apis.system.rest import config_rest, get_rest
import utilities.common as common_utils

try:
    import apis.yang.codegen.messages.errdisable_ext.ErrdisableExt as umf_errdis_ext
except ImportError:
    pass

def config_link_error_disable(dut,interface, **kwargs):
    """
    Usage -
    # To enable link_error_disable
    config_link_error_disable(vars.D1, interface=[vars.D1T1P1], config='yes')
    # To disable link_error_disable
    config_link_error_disable(vars.D1, interface=['Ethernet41'], config='no')
    # To enable link_errror_disable and to configure the parameters
    config_link_error_disable(vars.D1, interface=['Ethernet41-45'], flap_threshold=10, sampling_interval=10, recovery_interval=30, config='yes', config='yes')
    # To configure the parameters
    config_link_error_disable(vars.D1, intf_range=['Eth1/41','Eth1/45-1/48'], flap_threshold=10, sampling_interval=10, recovery_interval=30, config='yes')
    :param dut:
    :param interface:
    :param flap_threshold:
    :param sampling_interval:
    :param recovery_interval:
    :param kwargs:
    :return:
    """
    skip_error_check = kwargs.get("skip_error_check", False)
    cli_type = st.get_ui_type(dut, **kwargs)
    interface = make_list(interface)
    config = kwargs.get('config', 'yes')
    flap_threshold = kwargs.get('flap_threshold')
    sampling_interval = kwargs.get('sampling_interval')
    recovery_interval = kwargs.get('recovery_interval')

    if cli_type in get_supported_ui_type_list():
        port_hash_list = segregate_intf_list_type(intf=interface, range_format=False)
        all_intf_list = port_hash_list['intf_list_all']
        for each in all_intf_list:
            if config == 'yes':
                if flap_threshold and sampling_interval and recovery_interval:
                    err_dis_obj = umf_errdis_ext.Port(Name=each, FlapThreshold=flap_threshold, SamplingInterval=sampling_interval, RecoveryInterval=recovery_interval,  ErrorDisable='on')
                else:
                    err_dis_obj = umf_errdis_ext.Port(Name=each, FlapThreshold=3, SamplingInterval=30, RecoveryInterval=300, ErrorDisable='on')
                result = err_dis_obj.configure(dut, cli_type=cli_type)
            else:
                err_dis_obj = umf_errdis_ext.Port(Name=each, ErrorDisable='off')
                result = err_dis_obj.configure(dut, target_path='/link-flap', cli_type=cli_type)
            if not result.ok():
                if skip_error_check:
                    st.log('Negative Scenario: Errors/Expception expected')
                else:
                    st.log('test_step_failed: Config Error Disable {}'.format(result.data))
                return False
        return True
    elif cli_type == 'klish':
        port_hash_list = segregate_intf_list_type(intf=interface, range_format=True)
        all_intf_list = port_hash_list['intf_list_all']
        cmds = list()
        cmd = 'link-error-disable'
        for each_port in all_intf_list:
            if not is_a_single_intf(each_port):
                cmds.append("interface range {}".format(each_port))
            else:
                interface_details = get_interface_number_from_name(each_port)
                if not interface_details:
                    st.log("Interface details not found {}".format(interface_details))
                    return False
                cmds.append("interface {}".format(each_port))
        if config == 'yes':
            if flap_threshold and sampling_interval and recovery_interval :
                cmds.append("{} flap-threshold {} sampling-interval {} recovery-interval {}".format(cmd,flap_threshold, sampling_interval,
                                                                                     recovery_interval))
                cmds.append('exit')
            else:
                cmds.append(cmd)
        else:
            cmds.append("no {}".format(cmd))
            cmds.append('exit')

        output=st.config(dut, cmds, type=cli_type, skip_error_check=skip_error_check)
        if 'Error' in output:
            return False
    elif cli_type in ['rest-patch', 'rest-put']:
        port_hash_list = segregate_intf_list_type(intf=interface, range_format=False)
        all_intf_list = port_hash_list['intf_list_all']
        rest_urls = st.get_datastore(dut, 'rest_urls')
        if config == 'yes':
            rest_url = rest_urls['link_flap_error_disable_all_port']
            if flap_threshold and sampling_interval and recovery_interval:
                port_data=list()
                for each in all_intf_list:
                    port = {'name': each, 'config': {'name': each}, 'link-flap': {'config': {'error-disable': 'on',
                                                    'flap-threshold': int(flap_threshold), 'sampling-interval': int(sampling_interval),
                                                     'recovery-interval': int(recovery_interval)}}}
                    port_data.append(port)
                data1 = {"openconfig-errdisable-ext:errdisable-port": {"port": port_data}}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data1):
                    st.error("Failed to configure link flap error disable with params on interface through REST")
                    return False
            else:
                port_data = list()
                for each in all_intf_list:
                    port = {'name': each, 'config': {'name': each}, 'link-flap': {'config': {'error-disable': 'on',
                                                    'flap-threshold': 3, 'sampling-interval': 30,'recovery-interval': 300}}}
                    port_data.append(port)
                data2 = {"openconfig-errdisable-ext:errdisable-port": {"port": port_data}}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data2):
                    st.error("Failed to configure link flap error disable with params on interface {} through REST")
                    return False
        else:
            for each in all_intf_list:
                rest_url = rest_urls['delete_link_flap_config_port'].format(name=each)
                data = {"openconfig-errdisable-ext:link-flap": {"config": {"error-disable": "off"}}}
                if not config_rest(dut, json_data=data, http_method=cli_type, rest_url=rest_url):
                    st.error("Failed to disable link flap error disable on interface {} through REST")
                    return False

        return True
    elif cli_type == 'click':
        st.error("Unsupported cli type {}".format(cli_type))
        return False
    return True


def show_errdisable_link_flap(dut, **kwargs):
    """

    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = kwargs.get('cli_type', st.get_ui_type(dut))
    cli_type = force_cli_type_to_klish(cli_type)
    result = list()
    if cli_type == 'klish':
        show_command = "show errdisable link-flap"
        result = st.show(dut, show_command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        url = rest_urls['link_flap_error_disable_all_port']
        rest_output = get_rest(dut, rest_url=url)
        try:
            if rest_output['output'].get("openconfig-errdisable-ext:errdisable-port"):
                response = rest_output['output']['openconfig-errdisable-ext:errdisable-port'].get('port')
                for data in response:
                    res = dict()
                    if 'link-flap' in data:
                        res.update({'interface': data.get('name')})
                        for _, item in data['link-flap'].items():
                            res.update({'flap_threshold': item.get('flap-threshold')})
                            res.update({'recovery_interval': item.get('recovery-interval')})
                            res.update({'sampling_interval': item.get('sampling-interval')})
                            if 'status' in item:
                                res.update({'status': item.get('status').capitalize()})
                                res.update({'time_left': item.get('time-left')})
                        temp = res.copy()
                        result.append(temp)
        except Exception as e:
            st.error("DUT Failed to Display the Output: {}".format(e))
            return False
    elif cli_type == 'click':
        st.error("Unsupported cli type {}".format(cli_type))
        return False
    return result


def verify_errdisable_link_flap(dut, **kwargs):
    """
    verify_errdisable_link_flap(dut=vars.D1, verify_list= [{'interface': 'Ethernet10', 'flap_threshold': '10', 'status':'Errdisable'},
    {'interface': 'Ethernet11', 'flapthreshold': '20', 'status':'Not-errdisabled'}])
    verify_errdisable_link_flap(dut=vars.D1, verify_list= [{'interface': 'Ethernet10', 'flap_threshold': '10',
    'sampling_interval':30, 'recovery_interval' : 60 'status':'Errdisable'}])
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    #cli_type = 'klish' if cli_type in get_supported_ui_type_list() else cli_type
    try:
        if st.get_ui_type(dut) in ['rest-patch', 'rest-put'] and kwargs['verify_list'][0]['status'] == 'Off':
            return False

        time_left_data = dict()
        time_left = list()
        result = False

        if cli_type in get_supported_ui_type_list():
            for each in make_list(kwargs['verify_list']):
                if 'time_left' in each: 
                    cli_type = 'klish'
                    break

        if cli_type in get_supported_ui_type_list():
            filter_type = kwargs.get('filter_type', 'ALL')
            query_param_obj = common_utils.get_query_params(yang_data_type=filter_type, cli_type=cli_type)
            for each in make_list(kwargs['verify_list']):
                if not isinstance(each, dict):                
                    st.error("Elements of Verify_list must be dict")
                    return False
                err_dis_obj = umf_errdis_ext.Port(Name=each['interface'])
                if 'flap_threshold' in each: err_dis_obj.FlapThreshold = int(each['flap_threshold'])
                if 'sampling_interval' in each: err_dis_obj.SamplingInterval = int(each['sampling_interval'])
                if 'recovery_interval' in each: err_dis_obj.RecoveryInterval = int(each['recovery_interval'])
#                if 'status' in each: err_dis_obj.Status = each['status'].capitalize()
                if each['status'] == 'On': 
                    err_dis_obj.Status = each['status'].lower()
                else:
                    err_dis_obj.Status = each['status']
                result = err_dis_obj.verify(dut, match_subset=True, query_param=query_param_obj, target_path='/link-flap', cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Match Not Found for interface: {}'. format(each['interface']))
                    return False
            return True

        if not kwargs.get('verify_list'):
            st.error("verify_list is not provided")
            return result
        output = show_errdisable_link_flap(dut, **kwargs)
        if not output:
            return result
        for each in make_list(kwargs['verify_list']):
            if not isinstance(each, dict):
                st.error("Verify data should be list")
                return result
            if 'time_left' in each:
                time_left_val = int(each.get('time_left')) if each.get('time_left') != 'N/A' else each.get('time_left')
                if st.get_ui_type(dut, **kwargs) in ['rest-patch', 'rest-put'] and time_left_val == 'N/A':
                    time_left_val = None
                    each['time_left'] = None
                time_left_data.update({'interface':each.get('interface'), 'time_left':time_left_val})
                time_left.append(time_left_data)
            entries=filter_and_select(output, None, each)
            st.debug(entries)
            if not entries:
                st.error("match {} is not in output {}".format(each, output))
                return result
        result = True
        if time_left:
            for ea_ti in time_left:
                for ea_out in output:
                    if ea_ti.get('interface') == ea_out.get('interface'):
                        if isinstance(ea_ti.get('time_left'), int):
                            if ea_ti.get('time_left') == 0:
                                if int(ea_out.get('time_left')) == ea_ti.get('time_left'):
                                    result = True
                                else:
                                    result = False
                            else:
                                if int(ea_out.get('time_left')) < ea_ti.get('time_left'):
                                    result = True
                                else:
                                    result = False
                        else:
                            if ea_ti.get('time_left') == ea_out.get('time_left'):
                                result = True
                            else:
                                result = False
    except Exception as e:
        st.error(e)
        result = False
    return result


def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type
