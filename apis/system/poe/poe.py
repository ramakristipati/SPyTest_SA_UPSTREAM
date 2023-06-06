#############################################################################
# API Title    : Configure and Show commands of PoE from DUT.
# Author       : Venkat Moguluri
# Mail-id      : venkata.moguluri@broadcom.com
#############################################################################

from spytest import st
from utilities.common import filter_and_select, get_query_params, make_list
from utilities.utils import get_supported_ui_type_list

try:
    import apis.yang.codegen.messages.interfaces as umf_intf
    import apis.yang.codegen.messages.poe as umf_poe
    from apis.yang.utils.common import Operation

except ImportError:
    pass

def poe_reset(dut):
    """
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut)
    cli_type = 'klish' if cli_type in ['gnmi', 'click', 'rest-patch', 'rest-put', 'rest'] else cli_type
    if cli_type == "klish":
        command = "poe reset"
        return st.config(dut, command, type="klish", conf=False)

def show_poe(dut, **kwargs):
    """
    :param dut:
    :param global values:
    :param intf values:
    :param kwargs:
    :return:
    """
    sub_cmd = kwargs.get('sub_cmd', '')
    if sub_cmd:
        intf = kwargs.get('intf', 'all')
        command = "show poe port {} {}".format(sub_cmd, intf)
    else:
        command = "show poe"
    output = st.show(dut, command, type='klish')
    return output

def verify_poe(dut, **kwargs):

    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    threshold = float(kwargs.pop('threshold', 2))
    verify_values = kwargs.pop('verify_values', {})
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        power_manage_mode = {'static-priority': 'STATIC_PRIORITY', 'dynamic-priority': 'DYNAMIC_PRIORITY', 'Dynamic': 'DYNAMIC', 'Static': 'STATIC', 'class': 'CLASS'}
        poe_obj = umf_poe.Poe()
        poe_attr_list = {'firmware_version': ['FirmwareVersion', kwargs['firmware_version'] if 'firmware_version' in kwargs else None],
                         'power_management_mode': ['PowerManagementModel', power_manage_mode[kwargs['power_management_mode']] if 'power_management_mode' in kwargs else None]}
        for key in kwargs.keys():
            if key in poe_attr_list:
                if poe_attr_list[key][1] is not None:
                    setattr(poe_obj, poe_attr_list[key][0], poe_attr_list[key][1])
            else:
                st.error("Please add Argument {} to this variable \"poe_attr_list\" in API \"verify_poe\"".format(key))
                return False
        result = poe_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Match Not Found for the PoE Verify State values:', dut)
            return False

        actual_values = {
            'threshold_power': result.payload['openconfig-poe:poe']['global']['state']['power-threshold'],
            'total_power_available': result.payload['openconfig-poe:poe']['global']['state']['max-power-budget'],
            'total_power_consumed': result.payload['openconfig-poe:poe']['global']['state']['power-consumption'],
            'usage_threshold':result.payload['openconfig-poe:poe']['global']['state']['power-usage-threshold']
        }

        for each in verify_values.keys():
            if each in ['total_power_available', 'threshold_power', 'total_power_consumed', 'usage_threshold']:
                if not float(verify_values[each]) - threshold <= actual_values[each] <= float(verify_values[each]) + threshold:
                    st.error("Match not found for {}: Expected value is - {} with threshold of - {}, Actual value is - {} ".format(
                            each, float(verify_values[each]), threshold, actual_values[each]))
                    return False
    elif cli_type == 'klish':
        command = "show poe"
        output = st.show(dut, command, type='klish')
        if len(output) == 0:
            st.error('OUTPUT is empty')
            return False
        for each in kwargs.keys():
            match = {each: kwargs[each]}
            entries = filter_and_select(output, None, match)
            if not entries:
                st.error("Match not found for {}: Expected - {} Actual - {}".format(each, kwargs[each], output[0][each]))
                return False
        for each in verify_values.keys():
            entries = filter_and_select(output, None, match)
            if each in ['total_power_available', 'threshold_power', 'total_power_consumed', 'usage_threshold']:
                if not float(verify_values[each]) - threshold <= float(output[0][each]) <= float(verify_values[each]) + threshold:
                    st.error("Match not found for {}: Expected value is - {} with threshold of - {}, the Actual value is - {}".format(
                            each, float(verify_values[each]), threshold, entries[0][each]))
                    return False
    else:
        st.error('Unsupported CLI-TYPE provided')
        return False
    return True


def verify_poe_port_info(dut, intf_list, **kwargs):
    """
    :param dut:
    :param intf_list:
    :param verify_state:
    :param verify_values:
    :param kwargs:
    :return:
    """
    st.log("API : verify_poe_port_info")
    threshold = float(kwargs.pop('threshold', 5))
    verify_values = kwargs.pop('verify_values', {})
    sub_cmd = kwargs.pop('sub_cmd', 'info')
    cli_type = st.get_ui_type(kwargs.pop('cli_type', dut))
    intf_list = make_list(intf_list)
    for intf in intf_list:
        if cli_type == 'klish':
            output = show_poe(dut, sub_cmd=sub_cmd, intf=intf)
            if len(output) == 0:
                st.error('OUTPUT is empty')
                return False
            for each in kwargs.keys():
                match = {each: kwargs[each]}
                entries = filter_and_select(output, None, match)
                if not entries:
                    st.error("Match not found for {}: Expected - {} Actual - {}".format(each, kwargs[each], output[0][each]))
                    return False
            for each in verify_values.keys():
                match = {'port': intf}
                entries = filter_and_select(output, None, match)
                if each in ['output_power', 'output_voltage', 'output_current']:
                    if not float(verify_values[each]) - threshold <= float(entries[0][each]) <= float(verify_values[each]) + threshold:
                        st.error("Match not found for {}: Expected value is - {} with threshold of - {} But, the Actual value is - {}".format(
                                each, float(verify_values[each]), threshold, entries[0][each]))
                        return False
        elif cli_type in get_supported_ui_type_list():
            for intf in intf_list:
                status_dict = {'Disabled': 'DISABLED', 'Searching': 'SEARCHING', 'Delivering': 'DELIVERING_POWER', 'Test':'TEST', 'Fault':'FAULT', 'other-fault': 'OTHER_FAULT', 'requesting-power': 'REQUESTING_POWER', 'Overload':'OVERLOAD', 'Short':'SHORT'}
                fault_dict = {'No Error':'NO_ERROR', 'Ovlo':'OVLO', 'mps-absent':'MPS_ABSENT', 'Short':'SHORT', 'Overload':'OVERLOAD', 'power-denied':'POWER_DENIED', 'thermal-shutdown':'THERMAL_SHUTDOWN', 'status-failure':'STARTUP_FAILURE', 'Uvlo':'UVLO',
                              'hw-pin-disable':'HW_PIN_DISABLE', 'port-undefined':'PORT_UNDEFINED', 'internal-hw-fault':'INTERNAL_HW_FAULT', 'user-setting':'USER_SETTING', 'non-standard-pd':'NON_STANDARD_PD', 'Underload':'UNDERLOAD',
                              'pwr-budget-exceeded':'PWR_BUDGET_EXCEEDED', 'orr-capacitor-value':'OOR_CAPACITOR_VALUE', 'class-error':'CLASS_ERROR'}
                intf_obj = umf_intf.Interface(Name=intf)
                poe_attr_list = {
                    'status': ['Status', status_dict[kwargs['status']] if 'status' in kwargs else None],
                    'class_requested':['PowerClassRequested', kwargs['class_requested'] if 'class_requested' in kwargs else None],
                    'fault_status': ['FaultCode',fault_dict[kwargs['fault_status']] if 'fault_status' in kwargs else None]
                }

                for key in kwargs.keys():
                    if key in poe_attr_list:
                        if poe_attr_list[key][1] is not None:
                            setattr(intf_obj, poe_attr_list[key][0], poe_attr_list[key][1])
                    else:
                        st.error("Please add Argument {} to this variable \"poe_attr_list\" in API \"verify_poe_port_info\"".format(key))
                        return False

                filter_type = kwargs.get('filter_type', 'ALL')
                query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
                result = intf_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
                if not result.ok():
                    st.error('test_step_failed: Match Not Found for the PoE Verify State values:',dut)
                    return False
                actual_values = {
                'output_power' : result.payload['openconfig-interfaces:interface'][0]['openconfig-if-ethernet:ethernet']['openconfig-if-poe:poe']['state']['power-used'],
                'output_voltage' : result.payload['openconfig-interfaces:interface'][0]['openconfig-if-ethernet:ethernet']['openconfig-if-poe:poe']['state']['openconfig-if-poe-ext:output-voltage'],
                'output_current' : result.payload['openconfig-interfaces:interface'][0]['openconfig-if-ethernet:ethernet']['openconfig-if-poe:poe']['state']['openconfig-if-poe-ext:output-current']
                }
                st.banner("\n Actual output Power is - {} \n Actual output Voltage is - {} \n Actual output Current is - {}".format(actual_values['output_power'],actual_values['output_voltage'],actual_values['output_current']))

                for each in verify_values.keys():
                    if each in ['output_power', 'output_voltage', 'output_current']:
                        if not float(verify_values[each]) - threshold <= actual_values[each] <= float(verify_values[each]) + threshold:
                            st.error("Match not found for {}: Expected value is - {} with threshold of - {} But, the Actual value is - {} ".format(each, float(verify_values[each]),threshold,actual_values[each]))
                            return False
        else:
            st.error('Unsupported CLI-TYPE provided')
            return False
    return True


def config_poe_interface(dut, intf_list, **kwargs):
    """
    :param dut:
    :param operation:
    :param intf:
    :param kwargs:
    :return:
    """
    operation = kwargs.pop('operation', Operation.UPDATE)
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    intf_list = make_list(intf_list)
    if cli_type in get_supported_ui_type_list() + ['klish']:
        for intf in intf_list:
            intf_obj = umf_intf.Interface(Name=intf, **kwargs)
            result = intf_obj.configure(dut, operation=operation, cli_type=cli_type)
            if not result.ok():
                st.error('test_step_failed: Failed to configure the PoE on Interface {}'.format(result.data))
                return False
    else:
        st.error("Unsupported CLI_TYPE : {}".format(cli_type))
        return False
    return True


def config_poe(dut, **kwargs):
    """
    :param dut:
    :param operation:
    :param kwargs:
    :return:
    """
    operation = kwargs.pop('operation', Operation.UPDATE)
    cli_type = kwargs.pop('cli_type', st.get_ui_type(dut, **kwargs))
    if cli_type in get_supported_ui_type_list() + ['klish']:
        poe_obj = umf_poe.Poe(**kwargs)
        result = poe_obj.configure(dut, operation=operation, cli_type=cli_type)
        if not result.ok():
            st.error('test_step_failed: Failed to configure the PoE on globally: {}'.format(result.data))
            return False
    else:
        st.error("Unsupported CLI_TYPE : {}".format(cli_type))
        return False
    return True

