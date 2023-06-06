# This file contains the list of API's which performs PMS operations
# Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)

from spytest import st
from utilities.common import filter_and_select, make_list
import re
from apis.system.rest import config_rest, delete_rest, get_rest, rest_status
import utilities.utils as uutils

try:
    import apis.yang.codegen.messages.pms_ext as umf_pms
    from apis.yang.utils.common import Operation
except ImportError:
    pass


def config_port_mac_security(dut, interfaces, **kwargs):
    """
    API to config PMS on provided interface
    Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface: One or list of interfaces
    :param kwargs: {"config":"yes/no", "max_mac_count":{"intf_name":"max_mac_count_val"} (default:None), "action": {"intf_name":"action_val"}(default:protect)",
    "config_mac_count":"yes/no, "config_action":"yes/no"}
    :return: True/False
    """
    config = kwargs.get("config", "yes")
    enable = kwargs.get("enable", "yes")
    max_mac_count = kwargs.get("max_mac_count")
    action = kwargs.get("action", None)
    cli_type = st.get_ui_type(dut, **kwargs)
    config_mac_count = kwargs.get("config_mac_count", "yes")
    config_action = kwargs.get("config_action", "yes")
    intfs = make_list(interfaces)
    skip_error_check = kwargs.get("skip_error_check", False)
    if cli_type not in ["klish", "rest-patch", "rest-put"]+uutils.get_supported_ui_type_list():
        st.error("Unsupported CLI TYPE")
        return False
    if kwargs.get("max_mac_count") and not isinstance(kwargs.get("max_mac_count"), dict):
        st.error("MAX MAC count data should be provided per interface")
        return False
    if kwargs.get("action") and not isinstance(kwargs.get("action"), dict):
        st.error("ACTION data should be provided per interface")
        return False
    if cli_type in uutils.get_supported_ui_type_list():
        for interface in intfs:
            pms_kwargs = dict()
            pms_kwargs['cli_type'] = cli_type
            pms_kwargs['enable'] = enable
            pms_kwargs['config'] = config
            pms_kwargs["skip_error_check"] = skip_error_check
            if max_mac_count and max_mac_count.get(interface):
                pms_kwargs['max_mac_count'] = max_mac_count.get(interface)
            if action and action.get(interface):
                pms_kwargs['action'] = action.get(interface)
            result = config_pms_properties(dut, interface, **pms_kwargs)
            if not result: return result
        return True
    if cli_type == "klish":
        commands = list()
        for interface in intfs:
            if "PortChannel" in interface:
                po_int = uutils.get_interface_number_from_name(interface)
                commands.append("interface {} {}".format(po_int['type'], po_int['number']))
            else:
                commands.append("interface {}".format(interface))
            if config == "yes":
                commands.append("port-security enable")
                if max_mac_count and max_mac_count.get(interface):
                    commands.append("port-security maximum {}".format(max_mac_count.get(interface)))
                if action and action.get(interface):
                    commands.append("port-security violation {}".format(action.get(interface)))
            else:
                if config_mac_count == "no" and max_mac_count.get(interface):
                    commands.append("no port-security maximum")
                if config_action == "no" and action.get(interface):
                    commands.append("no port-security violation")
                commands.append("no port-security enable")
            commands.append("exit")
        output = st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        if "Error" in output:
            st.log(output)
            return False
    else:
        if config == "yes":
            url = st.get_datastore(dut, "rest_urls")["config_pms"]
            openconfig_payload = dict()
            openconfig_payload["openconfig-pms-ext:interfaces"] = dict()
            openconfig_payload["openconfig-pms-ext:interfaces"]["interface"] = list()
            for interface in intfs:
                interface_data = dict()
                interface_data["config"] = dict()
                interface_data["name"] = interface
                interface_data["config"]["name"] = interface
                interface_data["config"]["admin-enable"] = True
                if max_mac_count and max_mac_count.get(interface):
                    interface_data["config"]["maximum"] = max_mac_count.get(interface)
                if action and action.get(interface):
                    interface_data["config"]["violation"] = action.get(interface).upper()
                if interface_data:
                    openconfig_payload["openconfig-pms-ext:interfaces"]["interface"].append(interface_data)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=openconfig_payload):
                return False
        else:
            for interface in intfs:
                if config_mac_count == "no" and max_mac_count.get(interface):
                    url = st.get_datastore(dut, "rest_urls")["config_pms_on_intf_max"].format(interface)
                elif config_action == "no" and action.get(interface):
                    url = st.get_datastore(dut, "rest_urls")["config_pms_on_intf_violation"].format(interface)
                else:
                    url = st.get_datastore(dut, "rest_urls")["config_pms_on_interface"].format(interface)
            if not delete_rest(dut, rest_url=url, get_response=True):
                return False
    st.wait(5, "Added a DELAY to clear the FDB table after enable/disable PMS on an interface.")
    return True

def config_pms_properties(dut, interfaces, **kwargs):
    """
    API to configure individual PMS properties like max_mac_count, enable/disable, violation action
    :param dut:
    :param interfaces:
    :param kwargs: {"config":"yes/no", "max_mac_count":"100"}|{"config":"yes/no", "action":"PROTECT"}|{"config":"yes/no", "enable":True}
    :return:
    """
    skip_error_check = kwargs.get("skip_error_check", False)
    cli_type = st.get_ui_type(dut, **kwargs)
    intfs = make_list(interfaces)
    if cli_type not in ["klish", "rest-patch", "rest-put"]+uutils.get_supported_ui_type_list():
        st.error("Unsupported CLI TYPE")
        return False
    commands = list()
    if cli_type in uutils.get_supported_ui_type_list():
        try:
            st.log('config_pms_properties kwargs: {}'.format(kwargs))
            config = kwargs.get('config','yes')
            for interface in intfs:
                target_attr_list = list()
                pms_obj = umf_pms.Interface(Name=interface)
                if kwargs.get('max_mac_count'):
                    if config == "yes":
                        setattr(pms_obj, 'Maximum', int(kwargs['max_mac_count']))
                    else:
                        target_attr_list.append(getattr(pms_obj, 'Maximum'))
                if kwargs.get('action'):
                    if config == "yes":
                        setattr(pms_obj, 'Violation', kwargs['action'].upper())
                    else:
                        target_attr_list.append(getattr(pms_obj, 'Violation'))
                if kwargs.get('enable') == "yes" and config == "yes":
                    setattr(pms_obj, 'AdminEnable', True)
                elif kwargs.get('enable') == "no" and config == "no":
                    target_attr_list.append(getattr(pms_obj, 'AdminEnable'))
                if config == "yes":
                    operation = Operation.CREATE
                    result = pms_obj.configure(dut, operation=operation, cli_type=cli_type, skip_error_check=skip_error_check)
                else:
                    unconfig_params = dict()
                    if target_attr_list: unconfig_params.update({"target_attr":target_attr_list})
                    unconfig_params.update({"cli_type":cli_type})
                    result = pms_obj.unConfigure(dut, **unconfig_params)
                if not isinstance(result, tuple):
                    if not result.ok():
                        st.log('test_step_failed: Config Port Mac Security {}'.format(result.message))
                        return False
                else:
                    st.log(result[1])
                    return False
            return True
        except Exception as e:
            st.log(e)
            if skip_error_check:
                st.log("config_pms_properties: Negative scenario, Exception expected")
                return False
            else:
                raise e
    if cli_type == "klish":
        for interface in intfs:
            if "PortChannel" in interface:
                po_int = uutils.get_interface_number_from_name(interface)
                commands.append("interface {} {}".format(po_int['type'], po_int['number']))
            else:
                commands.append("interface {}".format(interface))
            if kwargs.get("enable"):
                if kwargs.get("config","yes") == "yes":
                    commands.append("port-security enable")
                else:
                    commands.append("no port-security enable")
            if kwargs.get("max_mac_count"):
                if kwargs.get("config","yes") == "yes":
                    commands.append("port-security maximum {}".format(kwargs.get("max_mac_count")))
                else:
                    commands.append("no port-security maximum")
            if kwargs.get("action"):
                if kwargs.get("config","yes") == "yes":
                    commands.append("port-security violation {}".format(kwargs.get("action")))
                else:
                    commands.append("no port-security violation")
        commands.append("exit")
        output = st.config(dut, commands, type=cli_type, skip_error_check=skip_error_check)
        if "Error" in output:
            st.log(output)
            return False
    else:
        for interface in intfs:
            if kwargs.get("enable"):
                pms_intf_url = st.get_datastore(dut, "rest_urls")["config_pms_on_intf_enable"].format(interface)
                if kwargs.get("config","yes") == "yes":
                    payload = dict()
                    payload["openconfig-pms-ext:admin-enable"] = "true"
                    if not config_rest(dut, http_method=cli_type, rest_url=pms_intf_url, json_data=payload):
                        return False
                else:
                    if not delete_rest(dut, rest_url=pms_intf_url, get_response=True):
                        return False
            if kwargs.get("max_mac_count"):
                pms_max_url = st.get_datastore(dut, "rest_urls")["config_pms_on_intf_max"].format(interface)
                if kwargs.get("config","yes") == "yes":
                    payload = dict()
                    payload["openconfig-pms-ext:maximum"] = "true"
                    if not config_rest(dut, http_method=cli_type, rest_url=pms_max_url, json_data=payload):
                        return False
                else:
                    if not delete_rest(dut, rest_url=pms_max_url, get_response=True):
                        return False
            if kwargs.get("action"):
                pms_violation_url = st.get_datastore(dut, "rest_urls")["config_pms_on_intf_violation"].format(interface)
                if kwargs.get("config","yes") == "yes":
                    payload = dict()
                    payload["openconfig-pms-ext:violation"] = "true"
                    if not config_rest(dut, http_method=cli_type, rest_url=pms_violation_url, json_data=payload):
                        return False
                else:
                    if not delete_rest(dut, rest_url=pms_violation_url, get_response=True):
                        return False
    return True


def show_port_mac_security(dut, **kwargs):
    """
    API to get the port mac security configuration in DUT as whole or on a provided interface
    Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface_name:
    :return: [{u'is_enabled': 'Y', u'security_action': 'PROTECT', u'fdb_count': '0', u'source_port': 'Ethernet0',
    u'vioaltion_count': '0', u'max_secure_addr': '1'},
    {u'is_enabled': 'N', u'security_action': 'PROTECT', u'fdb_count': '50', u'source_port': 'PortChannel10',
    u'vioaltion_count': '0', u'max_secure_addr': '100'}]
    """
    interface = kwargs.get("interface", None)
    cli_type = st.get_ui_type(dut)
    cli_type = 'klish' if cli_type in uutils.get_supported_ui_type_list() else cli_type
    if cli_type not in ["klish", "rest-patch", "rest-put"]:
        st.error("Unsupported CLI TYPE")
        return False
    if cli_type == "klish":
        command = "show port-security"
        if interface:
            command += " interface {}".format(interface)
        output = st.show(dut, command, type=cli_type, skip_error_check=True)
        if interface and output:
            if output[0]["is_enabled"] == "True":
                output[0].update({"is_enabled":"Y"})
            else:
                output[0].update({"is_enabled": "N"})
        return output
    else:
        output = list()
        if not interface:
            url = st.get_datastore(dut, "rest_urls")["config_pms"]
        else:
            url = st.get_datastore(dut, "rest_urls")["config_pms_on_interface"].format(interface)
        result = get_rest(dut, rest_url=url)
        if not result:
            st.error("No output")
            return False
        if result and rest_status(result["status"]):
            if result.get("output"):
                if result.get("output").get("openconfig-pms-ext:interfaces"):
                    pms_interfaces = result.get("output").get("openconfig-pms-ext:interfaces").get("interface")
                    for pms_intf in pms_interfaces:
                        res = dict()
                        res["source_port"] = pms_intf.get("name")
                        res["is_enabled"] = "Y" if pms_intf.get("config").get("admin-enable") == "true" else "N"
                        res["security_action"] = pms_intf.get("config").get("violation").replace("openconfig-pms-types:", "")
                        res["max_secure_addr"] = pms_intf.get("config").get("maximum")
                        if pms_intf.get("state") and pms_intf.get("state").get("oper-info"):
                            res["fdb_count"] = pms_intf.get("state").get("oper-info").get("fdb-count")
                            res["violation_count"] = pms_intf.get("state").get("oper-info").get("violation-count")
                        else:
                            res["fdb_count"] = res["vioaltion_count"] = 0
                        if res:
                            output.append(res)
        else:
            st.error("REST CALL failed")
        return output

def verify_port_security(dut, **kwargs):
    """
    API to verify the port security configuration with the provided verifcation data
    Author : Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    interface = kwargs.get("interface", None)
    verification_data = kwargs.get("verify_data", None)
    output = show_port_mac_security(dut, interface=interface)
    st.debug("VERIFICATION DATA: {}".format(verification_data))
    if not verification_data:
        st.error("No verification data provided")
        return False
    verification_list = make_list(verification_data)
    for data in verification_list:
        if not isinstance(data, dict):
            st.error("Entries in verification data should be of type dictionary")
            return False
        if not filter_and_select(output, None, data):
            st.error("Verification data - {} is not matching with configuration.".format(data))
            return False
    return True


def get_pms_from_running_config(dut, interface):
    """
    API to fetch the PMS configuration on provided interface from running configuration
    :param dut:
    :param interface:
    :return:
    """
    cli_type="klish"
    command = "show running-configuration interface {}".format(interface)
    output = st.config(dut, command, type=cli_type)
    port_security_commands = ["port-security enable", "port-security maximum", "port-security violation"]
    match_vals = re.findall(r"\s*port-security\s+\S+", output)
    st.debug("MATCH VALS - {}".format(match_vals))
    new_match_vals = [m.replace("\n ", "") for m in match_vals]
    st.debug("NEW MATCH VALS - {}".format(new_match_vals))
    for match in port_security_commands:
        if match not in new_match_vals:
            return False
    return True

def get_pms_violation_msgs(dut, interface, log_path=["/var/log/syslog.1", "/var/log/syslog"], expected_message_cnt=0, skip_error_check=True, date_range=[]):
    """
    API to get the PMS violation messages from syslog
    Author: Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param log_path:
    :param interface:
    :return:
    """
    logs_path = make_list(log_path)
    total_msg_cnt = 0
    for path in logs_path:
        if date_range and len(date_range)==2:
            command = "sudo sed -n '/{}/,/{}/p' {}".format(date_range[0], date_range[1], path)
        else:
            command = "sudo tail -20 {}".format(path)
        output = st.show(dut, command, skip_tmpl=True, skip_error_check=skip_error_check)
        if output:
            msgs = re.findall(r"Port Mac Security violation by MAC \S+ Port {}".format(interface), output)
            st.banner(msgs)
            if msgs:
                if len(msgs) != int(expected_message_cnt):
                    total_msg_cnt += len(msgs)
                else:
                    total_msg_cnt = len(msgs)
        if total_msg_cnt == expected_message_cnt:
            break
    st.debug("TOTAL VIOLATION MSG COUNT: {}".format(total_msg_cnt))
    return total_msg_cnt
