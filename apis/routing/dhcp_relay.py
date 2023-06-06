import re
import json
import ast
from natsort import natsorted

from spytest import st
from apis.system.rest import config_rest, get_rest, delete_rest
from apis.routing.ip import get_interface_ip_address
from apis.routing.ip_rest import get_subinterface_index

from utilities.utils import remove_last_line_from_string, get_interface_number_from_name
from utilities.utils import segregate_intf_list_type, is_a_single_intf
from utilities.utils import get_supported_ui_type_list, convert_intf_name_to_component
from utilities.utils import is_valid_ip_address
from utilities.common import filter_and_select,make_list, get_query_params, get_range_from_sequence

VLAN_SUB_INTERFACE_SEPARATOR = '.'

try:
    import apis.yang.codegen.messages.dhcp_snooping as umf_snooping
    import apis.yang.codegen.messages.relay_agent as umf_relay
    import apis.yang.codegen.messages.dhcp_snooping_rpc.DhcpSnoopingRpcRpc as umf_snooping_rpc
    from apis.yang.codegen.yang_rpc_service import YangRpcService

except ImportError:
    pass

get_phy_port = lambda intf: re.search(r"(\S+)\.\d+", intf).group(1) if re.search(r"(\S+)\.\d+", intf) else intf

def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


def dhcp_relay_config_add(dut, **kwargs):
    """
     Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param vlan:
    :param IP:
    :return:
    """

    kwargs.update({"action":"add"})
    return dhcp_relay_config(dut, **kwargs)


def dhcp_relay_config_remove(dut, **kwargs):
    """
    API to remove DHCP config
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param Vlan:
    :param IP:
    :return:
    """

    kwargs.update({"action": "remove"})
    return dhcp_relay_config(dut, **kwargs)


def subinterface_config(dut, **kwargs):
    """
    API for subinterface configuration
    :param dut:
    :param kwargs:
    :return:
    """
    cli_type = st.get_ui_type(dut, **kwargs)
    interface = kwargs.get("interface", None)
    skip_error_check = kwargs.get("skip_error_check", False)
    action = kwargs.get("action","add")
    if not interface:
        st.error("Required key 'interface' is not passed")
        return False
    if VLAN_SUB_INTERFACE_SEPARATOR not in interface:
        st.error("Not an subinterface: {}".format(interface))
        return False
    command = ""
    if cli_type == "click":
        if action == "add":
            command = "config subinterface add {}".format(interface)
        else:
            command = "config subinterface del {}".format(interface)
    elif cli_type == "klish":
        command = list()
        sub_intf_sep_idx = interface.find(VLAN_SUB_INTERFACE_SEPARATOR)
        vlan_id = interface[sub_intf_sep_idx + 1:]
        if interface.startswith("PortChannel"):
            intf_index = interface[len("PortChannel"):sub_intf_sep_idx]
            group = intf_index + VLAN_SUB_INTERFACE_SEPARATOR + vlan_id
            intf = "PortChannel " + group
        else:
            intf_index = interface[len("Ethernet"):sub_intf_sep_idx]
            group = intf_index + VLAN_SUB_INTERFACE_SEPARATOR + vlan_id
            intf = "Ethernet" + group

        if action == "add":
            command.append("interface {}".format(intf))
            command.append("encapsulation dot1q vlan-id {}".format(vlan_id))
        else:
            command.append("no interface {}".format(intf))
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    if command:
        st.debug("command is {}".format(command))
        output = st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
        if "Error" in output:
            if skip_error_check:
                return True
            else:
                return False
    return True

def subintf_get_shortname(intf):
    if intf is None:
        return None
    sub_intf_sep_idx = intf.find(VLAN_SUB_INTERFACE_SEPARATOR)
    if sub_intf_sep_idx == -1:
        return str(intf)
    sub_intf_idx = intf[(sub_intf_sep_idx+1):]
    if intf.startswith("Ethernet"):
        intf_index=intf[len("Ethernet"):sub_intf_sep_idx]
        return "Eth"+intf_index+VLAN_SUB_INTERFACE_SEPARATOR+sub_intf_idx
    elif intf.startswith("PortChannel"):
        intf_index=intf[len("PortChannel"):sub_intf_sep_idx]
        return "Po"+intf_index+VLAN_SUB_INTERFACE_SEPARATOR+sub_intf_idx
    else:
        return str(intf)

def dhcp_relay_config(dut, **kwargs):
    """
    API for DHCP relay configuration
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param kwargs:
    :return:
    """
    st.log('API_NAME: dhcp_relay_config, API_ARGS: {}'.format(locals()))
    cli_type = st.get_ui_type(dut, **kwargs)
    interface = kwargs.get("vlan", kwargs.get("interface", None))
    ip_address = make_list(kwargs.get('IP', []))
    ip_addr_lst = " ".join(ip_address)
    ip_family = kwargs.get("family", "ipv4")
    skip_error_check = kwargs.get("skip_error_check", False)
    action = kwargs.get("action","add")
    no_form = "" if action == "add" else "no"
    option = kwargs.get("option", None)

    if not interface:
        st.error("Required key 'interface' is not passed")
        return False

    if cli_type in get_supported_ui_type_list():
        if action =='remove' and 'IP' in kwargs: cli_type = 'klish'
        for ip_addr in ip_address:
            if not is_valid_ip_address(address=ip_addr, family=ip_family): cli_type = 'klish'
        st.log('Forcing the cli_type to Klish as action=remove or ip_address is invalid')
    #cli_type='klish' if cli_type in get_supported_ui_type_list() and action =='remove' and 'IP' in kwargs else cli_type
    if cli_type in get_supported_ui_type_list():
        if ip_family == 'ipv4':
            relay_obj = umf_relay.DhcpInterface(Id=interface)
        else:
            relay_obj = umf_relay.Dhcpv6Interface(Id=interface)

        dhcp_relay_attr ={
                 'IP' : ['HelperAddress', kwargs.get('IP', None)],
                 'src_interface' : ['SrcIntf', kwargs.get('src_interface', None)],
                 'vrf_name' : ['Vrf', kwargs.get('vrf_name', None)],
                 'max_hop_count' : ['MaxHopCount', int(kwargs['max_hop_count']) if 'max_hop_count' in kwargs else None],
                 'policy_action' : ['PolicyAction', kwargs['policy_action'].upper() if 'policy_action' in kwargs else None],
                 'vrf_select' : ['VrfSelect', 'ENABLE' if 'vrf_select' in kwargs else None],
                 'link_select' : ['LinkSelect', 'ENABLE' if 'link_select' in kwargs else None],
            }

        if action == 'add':
            for key, attr_value in  dhcp_relay_attr.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(relay_obj, attr_value[0], attr_value[1])
            result = relay_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config dhcp-relay {}'.format(result.data))
                return False


        if action == 'remove':
            for key, attr_value in  dhcp_relay_attr.items():
                if key in kwargs and attr_value[1] is not None:
                    target_attr = getattr(relay_obj, attr_value[0])
                    result = relay_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                    if not result.ok():
                        st.log('test_step_failed: Config dhcp-relay {}'.format(result.data))
                        return False

        return True

    command = ""
    if cli_type == "click":
        if ip_family == "ipv4":
            command = "config interface ip dhcp-relay {} {} {}".format(action, interface, ip_addr_lst)
        else:
            command = "config interface ipv6 dhcp-relay {} {} {}".format(action, interface, ip_addr_lst)
        if 'link_select' in kwargs:
            link_select = 'enable'
            command += " -link-select={}".format(link_select)
        if 'src_interface' in kwargs:
            src_interface = kwargs['src_interface']
            command += " -src-intf={}".format(src_interface)
        if 'max_hop_count' in kwargs:
            max_hop_count = kwargs['max_hop_count']
            command += " -max-hop-count={}".format(max_hop_count)
        if 'vrf_name' in kwargs and action == 'add':
            vrf_name = kwargs['vrf_name']
            command += " -vrf-name={}".format(vrf_name)
        if 'vrf_select' in kwargs:
            vrf_select = kwargs['vrf_select']
            command += " -vrf-select={}".format(vrf_select)
    elif cli_type == "klish":
        if ip_family not in ["ipv4", "ipv6"]:
            st.error("INVALID IP FAMILY -- {}".format(ip_family))
            return False
        command = list()
        '''
        interface_data = get_interface_number_from_name(interface)
        range=False
        if "-" in interface_data.get("number"):
            range=True
        range_cmd="" if not range else "range "
        command.append("interface {}{} {}".format(range_cmd,interface_data.get("type"), interface_data.get("number")))
        '''
        port_hash_list = segregate_intf_list_type(intf=interface, range_format=True)
        intf_range_list = port_hash_list['intf_list_all']
        for intf_range in intf_range_list:
            if not is_a_single_intf(intf_range):
                command.append('interface range {}'.format(intf_range))
            else:
                command.append('interface {}'.format(intf_range))
            ip_string = "ip" if ip_family == "ipv4" else "ipv6"
            if kwargs.get("link_select") and not kwargs.get("src_interface"):
                st.log("SRC INTF needed for LINK SELECT operation")
                #return False
            if ip_addr_lst:
                cmd = "{} {} dhcp-relay {}".format(no_form, ip_string, ip_addr_lst)
                if 'vrf_name' in kwargs and action == 'add':
                    cmd += " vrf-name {}".format(kwargs['vrf_name'])
                command.append(cmd)
            if action == 'remove':
                if 'link_select' in kwargs:
                    command.append("{} {} dhcp-relay link-select".format(no_form, ip_string))
                if 'src_interface' in kwargs:
                    command.append("{} {} dhcp-relay source-interface".format(no_form, ip_string))
                if option =='src-intf':
                    if 'src_interface' not in kwargs:
                        command.append("{} {} dhcp-relay source-interface".format(no_form, ip_string))
            if action == 'add':
                if 'src_interface' in kwargs:
                    src_interface = ' {}'.format(kwargs['src_interface'])
                    command.append("{} {} dhcp-relay source-interface{}".format(no_form, ip_string, src_interface))
                if 'link_select' in kwargs:
                    command.append("{} {} dhcp-relay link-select".format(no_form, ip_string))
            if 'max_hop_count' in kwargs:
                max_hop_count = ' {}'.format(kwargs['max_hop_count']) if action == 'add' else ''
                command.append("{} {} dhcp-relay max-hop-count{}".format(no_form, ip_string, max_hop_count))
            if 'vrf_select' in kwargs:
                vrf_select = kwargs['vrf_select']
                command.append("{} {} dhcp-relay vrf-select".format(no_form, ip_string))
            if 'policy_action' in kwargs:
                policy_action = ' {}'.format(kwargs['policy_action']) if action == 'add' else ''
                command.append("{} {} dhcp-relay policy-action{}".format(no_form, ip_string, policy_action))
            command.append("exit")
    elif cli_type in ["rest-patch", "rest-put"]:
        if ip_family not in ["ipv4", "ipv6"]:
            st.error("INVALID IP FAMILY -- {}".format(ip_family))
            return False
        ip_string = "" if ip_family == "ipv4" else "v6"
        #if kwargs.get("link_select") and not kwargs.get("src_interface"):
        #    st.log("SRC INTF needed for LINK SELECT operation")
        #    return False
        config_data = {"openconfig-relay-agent:config": {"id": interface}}
        config_data1 = {"openconfig-relay-agent:config": {}}
        rest_urls = st.get_datastore(dut, 'rest_urls')
        result = True
        if ip_address:
            if action == 'add':
                config_data["openconfig-relay-agent:config"].update({"helper-address": ip_address})
                if kwargs.get('vrf_name'):
                    config_data["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:vrf": kwargs['vrf_name']})
            else:
                for ip in ip_address:
                    if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_address_config'.format(ip_string)].format(id=interface, helper_address=ip)):
                        st.error("Failed to delete DHCP-Relay Helper-Address: {}".format(ip))
                        return False
        if 'src_interface' in kwargs:
            if action == 'add':
                config_data["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:src-intf": kwargs['src_interface']})
            else:
                if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_src_intf_config'.format(ip_string)].format(id=interface)):
                    st.error("Failed to delete DHCP-Relay source-interface on interface: {}".format(interface))
                    return False
        if 'link_select' in kwargs:
            if action == 'add':
                config_data1 = {"openconfig-relay-agent:config": {"openconfig-relay-agent-ext:link-select": "ENABLE"}}
            else:
                if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_link_select_config'.format(ip_string)].format(id=interface)):
                    st.error("Failed to delete DHCP-Relay link-select")
                    return False
        if 'max_hop_count' in kwargs:
            if action == 'add':
                config_data["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:max-hop-count": int(kwargs['max_hop_count'])})
            else:
                if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_max_hop_count_config'.format(ip_string)].format(id=interface)):
                    st.error("Failed to delete DHCP-Relay max-hop-count on interface: {}".format(interface))
                    return False
        if 'vrf_select' in kwargs:
            if action == 'add':
                if 'link_select' in kwargs:
                    config_data1["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:vrf-select": "ENABLE"})
                else:
                    config_data1 = {"openconfig-relay-agent:config": {"openconfig-relay-agent-ext:vrf-select": "ENABLE"}}
            else:
                if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_vrf_select_config'.format(ip_string)].format(id=interface)):
                    st.error("Failed to delete DHCP-Relay vrf-select on interface: {}".format(interface))
                    return False
        if 'policy_action' in kwargs:
            if action == 'add':
                config_data["openconfig-relay-agent:config"].update({"openconfig-relay-agent-ext:policy-action": kwargs['policy_action'].upper()})
            else:
                if not delete_rest(dut, rest_url=rest_urls['dhcp{}_relay_policy_action_config'.format(ip_string)].format(id=interface)):
                    st.error("Failed to delete DHCP-Relay policy_action on interface: {}".format(interface))
                    return False
        if len(config_data["openconfig-relay-agent:config"]) > 1:
            if not config_rest(dut, rest_url=rest_urls['dhcp{}_relay_config'.format(ip_string)].format(id=interface), http_method=cli_type, json_data=config_data):
                result = False

        if len(config_data1["openconfig-relay-agent:config"]) >= 1:
            if not config_rest(dut, rest_url=rest_urls['dhcp{}_relay_agent_information_config'.format(ip_string)].format(id=interface), http_method=cli_type, json_data=config_data1):
                result = False
        if not result:
             st.error("Failed to configure DHCP-Relay parameters")
             return False
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False
    if command:
        st.debug("command is {}".format(command))
        output = st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
        if "Error" in output:
            if skip_error_check:
                return True
            else:
                return False
    return True


def dhcp_relay_option_config(dut, **kwargs):
    """
    API for DHCP relay option configuration like link-selection, src-interface and max-hop count
    :param dut:
    :param kwargs:
    :return:
    """
    st.log('API_NAME: dhcp_relay_option_config, API_ARGS: {}'.format(locals()))
    interface = kwargs.get("vlan", kwargs.get("interface", None))
    option = kwargs.get("option", None)
    src_interface = kwargs.get("src_interface", None)
    hop_count = kwargs.get("max_hop_count",0)
    policy_action = kwargs.get("policy_action",None)
    ip_family = kwargs.get("family", "ipv4")
    cli_type = st.get_ui_type(dut, **kwargs)
    skip_error_check = kwargs.get("skip_error_check", False)
    action = kwargs.get("action","add")
    no_form = "" if action == "add" else "no"

    if not (interface):
        st.error("required interface value is not passed")
        return False

    if cli_type in get_supported_ui_type_list():
        if option =='max-hop-count':
            kwargs[option.replace('-','_')] = hop_count
        elif option =='policy-action':
            kwargs[option.replace('-','_')] = policy_action
        else:
            kwargs[option.replace('-','_')] = option

        return dhcp_relay_config(dut, **kwargs)

    command = ""
    if cli_type == "click":
        if ip_family == "ipv4":
            if option == "policy-action":
                command = "config interface ip dhcp-relay policy-action {} {}".format(interface,policy_action)
            else:
                command = "config interface ip dhcp-relay {} {} {}".format(option, action, interface)
        else:
            command = "config interface ipv6 dhcp-relay {} {} {}".format(option, action, interface)

        if action == "add":
            if option == "src-intf":
                if not src_interface:
                    st.log("required src_interface value is not passed")
                    return False
                command += " {}".format(src_interface)
            if option == "max-hop-count":
                command += " {}".format(hop_count)
    elif cli_type == "klish":
        if option == "src-intf" and not src_interface:
            if no_form != 'no':
                st.error("Required 'src_interface' value is not passed")
                return False
        if option == 'max-hop-count':
            kwargs[option.replace('-','_')] = hop_count
        elif option == 'policy-action':
            kwargs[option.replace('-','_')] = policy_action
        else:
            kwargs[option.replace('-','_')] = option

        return dhcp_relay_config(dut, **kwargs)

        '''
        command = list()
        interface_data = get_interface_number_from_name(interface)
        command.append("interface {} {}".format(interface_data.get("type"), interface_data.get("number")))
        cmd = ""
        if ip_family == "ipv4":
            cmd += "{} ip dhcp-relay".format(no_form)
        else:
            cmd += "{} ipv6 dhcp-relay".format(no_form)
        if option == "src-intf":
            if not src_interface:
                if no_form != 'no':
                    st.error("Required 'src_interface' value is not passed")
                    return False
            src_interface = src_interface if no_form != "no" else ""
            cmd += " source-interface {}".format(src_interface)
        if option == "max-hop-count":
            max_hop_count = hop_count if no_form != "no" else ""
            cmd += " max-hop-count {}".format(max_hop_count)
        if option == "link-select":
            cmd += " link-select"
        if option == "vrf-select":
            cmd += " vrf-select"
        if option == "policy-action":
            cmd += " policy-action {}".format(policy_action)
        command.append(cmd)
        '''
    elif cli_type in ["rest-patch", "rest-put"]:
        config_dict = {'action': action, 'interface': interface, 'family': ip_family, 'cli_type': cli_type}
        if option == "src-intf":
            if not src_interface:
                if no_form != 'no':
                    st.error("required src_interface value is not passed")
                    return False
            config_dict['src_interface'] = src_interface
        elif option == "max-hop-count":
            config_dict['max_hop_count'] = hop_count
        elif option == "link-select":
            config_dict['link_select'] = True
        elif option == "vrf-select":
            config_dict['vrf_select'] = True
        elif option == "policy-action":
            config_dict['policy_action'] = policy_action
        else:
            st.error("Invalid option: {}".format(option))
            return False
        st.banner(config_dict)
        if not dhcp_relay_config(dut, **config_dict):
            st.error("Failed to set the option: {}".format(option))
            return False
    else:
        st.error("Unsupported CLI_type: {}".format(cli_type))
        return False
    if command:
        st.debug("command is {}".format(command))
        output = st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
        if "Error" in output:
            if skip_error_check:
                return True
            else:
                return False
    return True


def dhcp_relay_show(dut, family="ipv4", interface=None, cli_type=""):
    """
    API to show the DHCP relay brief output
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type='klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type in ['click', 'klish']:
        ip_val = "ip" if family == "ipv4" else "ipv6"
        command = "show {} dhcp-relay brief".format(ip_val)
        filter = "-w" if cli_type == "click" else ""
        if interface:
            command += " | grep {} {}".format(filter, interface)
        return st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        return _get_rest_brief_dhcp_relay_data(dut, family=family)
    else:
        st.error('Unsupported CLI_TYPE: {}'.format(cli_type))
        return False


def dhcp_relay_detailed_show(dut, interface="", family="ipv4", cli_type=""):
    """
    API to show the DHCP relay detailed output
    :param dut:
    :return:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type='klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type in ['click', 'klish']:
        ip_val = "ip" if family == "ipv4" else "ipv6"
        if interface:
            command = "show {} dhcp-relay detailed {}".format(ip_val, interface)
        else:
            command = "show {} dhcp-relay detailed".format(ip_val)
        return st.show(dut, command, type=cli_type)
    elif cli_type in ['rest-patch', 'rest-put']:
        return _get_rest_detailed_dhcp_relay_data(dut, interface=interface, family=family)
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def dhcp_relay_restart(dut):
    """
    API to restart DHCP relay
    :param dut:
    :param vlan:
    :param IP:
    :return:
    """
    st.config(dut, "systemctl restart dhcp_relay")
    return True


def dhcp_client_start(dut, interface, family="ipv4", stateless_client='no', run_bckgrnd=False):
    """
    API to start DHCLIENT in foreground for v4 and background for v6
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :type dut:
    :param portlist:
    :type portlist:
    """
    if interface is not None:
        interface = convert_intf_name_to_component(dut, intf_list=interface)
        '''
        if '/' in interface:
            interface = st.get_other_names(dut,[interface])[0]
        '''
    #interface = subintf_get_shortname(interface)

    v6_opt = "" if family == "ipv4" else "-6"
    run_bckgrnd = True if (family == "ipv6" or run_bckgrnd) else False
    bckgrd = "&" if run_bckgrnd else ""
    client_request = "-S" if stateless_client == "yes" else ""
    command = "dhclient {} {} {} {}".format(v6_opt, client_request, interface, bckgrd)
    output = st.config(dut, command, skip_error_check=True)
    if bckgrd:
        output = remove_last_line_from_string(output)
        if output:
            return output.split(" ")[1]
        else:
            return None
    else:
        return True


def dhcp_client_stop(dut, interface, pid=None, family="ipv4", skip_error_check=False, show_interface=False):
    """
    API to stop DHCP client either by using process id or dhclient
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :type dut:
    :param portlist:
    :type portlist:
    """
    if interface is not None:
        interface_name = convert_intf_name_to_component(dut, intf_list=interface)
        '''
        if '/' in interface:
            interface = st.get_other_names(dut,[interface])[0]
        '''
    #interface_name = subintf_get_shortname(interface)

    v6_opt = "" if family == "ipv4" else "-6"
    command = "kill -9 {}".format(pid) if pid else  "dhclient {} -r {}".format(v6_opt, interface_name)
    st.config(dut, command, skip_error_check=skip_error_check)
    if show_interface:
        get_interface_ip_address(dut, interface_name=interface, family=family)
    return True


def get_dhcp_relay_statistics(dut, interface="", family="ipv4", cli_type="", skip_error_check=True):
    """
    API to get DHCP relay statistics
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :type dut:
    :param interface:
    :type interface:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    cli_type='klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type in ['click', 'klish']:
        ip_val = "ip" if family == "ipv4" else "ipv6"
        if interface:
            command = "show {} dhcp-relay statistics {}".format(ip_val, interface)
        else:
            command = "show {} dhcp-relay statistics".format(ip_val)
        return st.show(dut, command, type=cli_type, skip_error_check=skip_error_check)
    elif cli_type in ['rest-patch', 'rest-put']:
        return _get_rest_dhcp_relay_statistics(dut, interface=interface, family=family)
    else:
        st.error("Unsupported CLI_TYPE: {}".format(cli_type))
        return False


def clear_statistics(dut, interface, family="ipv4", cli_type=''):
    """
    API to clear the DHCP RELAY statistics
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface:
    :param family:
    :param cli_type:
    :return:
    """
    if not cli_type: cli_type = st.get_ui_type(dut)
    cli_type='klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    ip_val = "ip" if family == "ipv4" else "ipv6"
    if cli_type =='click':
        command = "sonic-clear {} dhcp-relay statistics {}".format(ip_val, interface)
    elif cli_type =='klish':
        command = "clear {} dhcp-relay statistics {}".format(ip_val,interface)
    return st.config(dut, command, type=cli_type)


def debug(dut, interface, family="ipv4", cli_type="click"):
    """
    API to enable debug for DHCP relay interface
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :return:
    """
    ip_val = "ip" if family == "ipv4" else "ipv6"
    command = "debug {} dhcp-relay {}".format(ip_val, interface)
    return st.config(dut, command, type=cli_type)


def verify_dhcp_relay(dut, interface, dhcp_relay_addr, family="ipv4", cli_type=""):
    """
    API to verify DHCP RELAY configuration
    Author Chaitanya Vella (chaitanya-vella.kumar@broadcom.com)
    :param dut:
    :param interface:
    :param dhcp_relay_addr:
    """
    cli_type = st.get_ui_type(dut, cli_type=cli_type)
    if not is_valid_ip_address(address=dhcp_relay_addr, family=family):
        st.log('Forcing to Klish for invalid address, as MDI throws ValueError')
        cli_type = 'klish'
    if cli_type in get_supported_ui_type_list():
        if family == 'ipv4':
            relay_obj = umf_relay.DhcpInterface(Id=interface)
        else:
            relay_obj = umf_relay.Dhcpv6Interface(Id=interface)

        dhcp_relay_attr ={
                'dhcp_relay_addr' : ['HelperAddress', dhcp_relay_addr],
             }
        st.banner(dhcp_relay_attr)
        for _, attr_value in  dhcp_relay_attr.items():
            setattr(relay_obj, attr_value[0], attr_value[1])
        st.log('***IETF_JSON***: {}'.format(relay_obj.get_ietf_json()))
        result = relay_obj.verify(dut,match_subset=True,cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verify dhcp-relay {}'.format(result.data))
            return False
        return True

    output = dhcp_relay_show(dut, family=family, interface=interface, cli_type=cli_type)
    dhcp_relay_address = make_list(dhcp_relay_addr)
    filter=list()
    for address in dhcp_relay_address:
        match = {"intf": interface, "dhcprelay_addr": address}
        filter.append(match)
    entries = filter_and_select(output, ["intf"], filter)
    return True if entries else False


def verify_dhcp_relay_detailed(dut, interface, **kwargs):
    """
    API to verify DHCP RELAY datailed configuration
    :param dut:
    """
    #src_interface = kwargs.get("src_interface", None)
    #link_select = kwargs.get("link_select", None)
    #hop_count = kwargs.get("max_hop_count",None)
    ip_family = kwargs.get("family", "ipv4")
    cli_type = st.get_ui_type(dut, **kwargs)
    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        if ip_family == 'ipv4':
            relay_obj = umf_relay.DhcpInterface(Id=interface)
        else:
            relay_obj = umf_relay.Dhcpv6Interface(Id=interface)

        dhcp_relay_attr ={
                 'IP' : ['HelperAddress', kwargs.get('IP', None)],
                 'src_interface' : ['SrcIntf', kwargs.get('src_interface', None)],
                 'vrf_name' : ['Vrf', kwargs.get('vrf_name', None)],
                 'max_hop_count' : ['MaxHopCount', int(kwargs['max_hop_count']) if 'max_hop_count' in kwargs else None],
                 'policy_action' : ['PolicyAction', kwargs['policy_action'].upper() if 'policy_action' in kwargs else None],
                 'vrf_select' : ['VrfSelect', kwargs['vrf_select'].upper() if 'vrf_select' in kwargs else None],
                 'link_select' : ['LinkSelect',kwargs['link_select'].upper()  if 'link_select' in kwargs else None],
                 'circuitid_format' : ['CircuitId', kwargs.get('circuitid_format', None)]
            }
        st.banner(dhcp_relay_attr)
        for key, attr_value in  dhcp_relay_attr.items():
            if key in kwargs and attr_value[1] is not None:
                setattr(relay_obj, attr_value[0], attr_value[1])
        st.log('***IETF_JSON***: {}'.format(relay_obj.get_ietf_json()))
        result = relay_obj.verify(dut,match_subset=True, query_param=query_param_obj,cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verify dhcp-relay {}'.format(result.data))
            return False
        return True

    output = dhcp_relay_detailed_show(dut, interface, family=ip_family, cli_type=cli_type)
    if output == 0:
        st.error("Output is Empty")
        return False
    if kwargs.get("cli_type"):
        del kwargs["cli_type"]
    if kwargs.get("family"):
        del kwargs["family"]
    for each in kwargs.keys():
        if 'src_interface' in each or 'link_select' in each or 'max_hop_count' in each \
            or 'vrf_name' in each or 'policy_action' in each or 'vrf_select' in each or 'circuitid_format' in each:
            match = {each: kwargs[each]}
            st.log(match)
            entries = filter_and_select(output, None, match)
            st.log("entries {}".format(entries))
            if not entries:
                st.log("{} and {} is not match ".format(each, kwargs[each]))
                return False
    if kwargs.get("server_addr"):
        server_addr = ""
        for result in output:
            if result.get("server_addr"):
                server_addr = result.get("server_addr")
                break
        st.debug("SERVER ADDR: {}".format(server_addr))
        if not server_addr:
            st.log("Server address from output is empty")
            return False
        if  kwargs.get("server_addr") not in server_addr.split(", "):
            st.log("Provided server address is not matching with configured one")
            return False
    return True


def verify_dhcp_relay_statistics(dut, **kwargs):
    """
    API to verify the DHCP relay statistics
    :param dut:
    :param kwargs:
    Kwargs contains the key value pair to verify, values of each key can be <exact number> for exact match,
    "non-zero" for matching of positive non zero values
    :return:
    """
    interface=kwargs.get("interface", "")
    family = kwargs.get("family", "ipv4")
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type='klish' if cli_type in get_supported_ui_type_list() else cli_type
    if kwargs.get("interface"):
        del kwargs["interface"]
    if kwargs.get("family"):
        del kwargs["family"]
    if kwargs.get("cli_type"):
        del kwargs["cli_type"]
    output = get_dhcp_relay_statistics(dut, interface=interface, family=family, cli_type=cli_type)
    if not output:
        st.error("No output found - {}".format(output))
        return False
    result = 0
    for key,value in kwargs.items():
        if value not in [0, "0", "non-zero"]:
            st.log("Unsupported values provided")
            return False
        if key in output[0]:
            if value == "non-zero":
                if str(output[0][key]) <= "0":
                    result += 1
                    break
            elif str(value) == "0":
                if str(output[0][key]) != "0":
                    result += 1
                    break
            else:
                if str(output[0][key]) != str(value):
                    result += 1
                    break
        else:
            st.log("Specified KEY string is not found in output")
            return False
    if result > 0:
        st.log("Mismatch observed in provided key value pair verification")
        return False
    else:
        return True


def _get_rest_detailed_dhcp_relay_data(dut, interface="", family='ipv4'):
    """
    To get the dhcp-relay detailed data
    Author Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param interface:
    :param family:
    :return:
    """
    retval = list()
    rest_urls = st.get_datastore(dut, 'rest_urls')
    ip_string = '' if family == 'ipv4' else 'v6'
    if not interface:
        output = get_interface_ip_address(dut, family=family)
        interfaces = {entry['interface'] for entry in output}
        interfaces.discard('eth0')
    else:
        interfaces = make_list(interface)
    for intf in interfaces:
        url = rest_urls['dhcp{}_relay_config'.format(ip_string)].format(id=intf)
        url1 = rest_urls['dhcp{}_relay_agent_information_config'.format(ip_string)].format(id=intf)
        out = get_rest(dut, rest_url=url)
        out1 = get_rest(dut, rest_url=url1)
        if isinstance(out, dict) and out.get('output') and out['output'].get('openconfig-relay-agent:config'):
            data = out['output']['openconfig-relay-agent:config']
            temp = dict()
            temp['intf'] = intf
            temp['server_addr'] = ", ".join(data['helper-address']) if data.get('helper-address') and isinstance(data['helper-address'], list) else ''
            temp['vrf_name'] = data['openconfig-relay-agent-ext:vrf'] if data.get('openconfig-relay-agent-ext:vrf') else 'Not Configured'
            temp['src_interface'] = data['openconfig-relay-agent-ext:src-intf'] if data.get('openconfig-relay-agent-ext:src-intf') else 'Not Configured'
            temp['max_hop_count'] = str(data['openconfig-relay-agent-ext:max-hop-count']) if data.get('openconfig-relay-agent-ext:max-hop-count') else '10'
            if family == 'ipv4':
                temp['policy_action'] = data['openconfig-relay-agent-ext:policy-action'].lower() if data.get('openconfig-relay-agent-ext:policy-action') else 'discard'
            if isinstance(out1, dict) and out1.get('output') and out1['output'].get('openconfig-relay-agent:config'):
                data1 = out1['output']['openconfig-relay-agent:config']
                temp['vrf_select'] = data1['openconfig-relay-agent-ext:vrf-select'].lower() if data1.get('openconfig-relay-agent-ext:vrf-select') else 'disable'
                if family == 'ipv4':
                    temp['link_select'] = data1['openconfig-relay-agent-ext:link-select'].lower() if data1.get('openconfig-relay-agent-ext:link-select') else 'disable'
            else:
                temp['vrf_select'] = 'disable'
                if family == 'ipv4':
                    temp['link_select'] = 'disable'
            retval.append(temp)
    st.debug(retval)
    return retval


def _get_rest_brief_dhcp_relay_data(dut, family='ipv4'):
    """
    To get the dhcp-relay brief data
    Author Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param family:
    :return:
    """
    retval = list()
    rest_urls = st.get_datastore(dut, 'rest_urls')
    ip_string = '' if family == 'ipv4' else 'v6'
    output = get_interface_ip_address(dut, family=family)
    interfaces = {entry['interface'] for entry in output}
    interfaces.discard('eth0')
    for intf in interfaces:
        url = rest_urls['get_dhcp{}_relay_helper_address'.format(ip_string)].format(id=intf)
        out = get_rest(dut, rest_url=url)
        if isinstance(out, dict) and out.get('output') and out['output'].get('openconfig-relay-agent:helper-address') and isinstance(out['output']['openconfig-relay-agent:helper-address'], list):
            addresses = out['output']['openconfig-relay-agent:helper-address']
            for address in addresses:
                temp = dict()
                temp['intf'] = intf
                temp['dhcprelay_addr'] = address
                retval.append(temp)
    st.debug(retval)
    return retval


def _get_rest_dhcp_relay_statistics(dut, interface="", family='ipv4'):
    """
    To get the dhcp-relay statistics data
    Author Jagadish Chatrasi (jagadish.chatrasi@broadcom.com)
    :param dut:
    :param interface:
    :param family:
    :return:
    """
    retval = list()
    rest_urls = st.get_datastore(dut, 'rest_urls')
    ip_string = '' if family == 'ipv4' else 'v6'
    if not interface:
        output = get_interface_ip_address(dut, family=family)
        interfaces = {entry['interface'] for entry in output}
        interfaces.discard('eth0')
    else:
        interfaces = make_list(interface)
    for intf in interfaces:
        url = rest_urls['get_dhcp{}_relay_counters'.format(ip_string)].format(id=intf)
        out = get_rest(dut, rest_url=url)
        if isinstance(out, dict) and out.get('output') and out['output'].get('openconfig-relay-agent:counters') and isinstance(out['output']['openconfig-relay-agent:counters'], dict):
            data = out['output']['openconfig-relay-agent:counters']
            temp = dict()
            if family == 'ipv4':
                temp['bootrequest_msgs_received_by_the_relay_agent'] = str(data['bootrequest-received']) if data.get('bootrequest-received') else '0'
                temp['bootrequest_msgs_forwarded_by_the_relay_agent'] = str(data['bootrequest-sent']) if data.get('bootrequest-sent') else '0'
                temp['bootreply_msgs_forwarded_by_the_relay_agent'] = str(data['bootreply-sent']) if data.get('bootreply-sent') else '0'
                temp['dhcp_ack_msgs_sent_by_the_relay_agent'] = str(data['dhcp-ack-sent']) if data.get('dhcp-ack-sent') else '0'
                temp['dhcp_decline_msgs_received_by_the_relay_agent'] = str(data['dhcp-decline-received']) if data.get('dhcp-decline-received') else '0'
                temp['dhcp_discover_msgs_received_by_the_relay_agent'] = str(data['dhcp-discover-received']) if data.get('dhcp-discover-received') else '0'
                temp['dhcp_inform_msgs_received_by_the_relay_agent'] = str(data['dhcp-inform-received']) if data.get('dhcp-inform-received') else '0'
                temp['dhcp_nack_msgs_sent_by_the_relay_agent'] = str(data['dhcp-nack-sent']) if data.get('dhcp-nack-sent') else '0'
                temp['dhcp_offer_msgs_sent_by_the_relay_agent'] = str(data['dhcp-offer-sent']) if data.get('dhcp-offer-sent') else '0'
                temp['dhcp_release_msgs_received_by_the_relay_agent'] = str(data['dhcp-release-received']) if data.get('dhcp-release-received') else '0'
                temp['dhcp_request_msgs_received_by_the_relay_agent'] = str(data['dhcp-request-received']) if data.get('dhcp-request-received') else '0'
                temp['number_of_dhcp_pkts_drpd_due_to_an_invd_opcode'] = str(data['invalid-opcode']) if data.get('invalid-opcode') else '0'
                temp['number_of_dhcp_pkts_drpd_due_to_an_invd_option'] = str(data['invalid-options']) if data.get('invalid-options') else '0'
                temp['total_nbr_of_dhcp_pkts_drpd_by_the_relay_agent'] = str(data['total-dropped']) if data.get('total-dropped') else '0'
            else:
                temp['dhcpv6_advt_msgs_sent_by_the_relay_agent'] = str(data['dhcpv6-adverstise-sent']) if data.get('dhcpv6-adverstise-sent') else '0'
                temp['dhcpv6_confirm_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-confirm-received']) if data.get('dhcpv6-confirm-received') else '0'
                temp['dhcpv6_decline_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-decline-received']) if data.get('dhcpv6-decline-received') else '0'
                temp['dhcpv6_info_rqst_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-info-request-received']) if data.get('dhcpv6-info-request-received') else '0'
                temp['dhcpv6_rebind_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-rebind-received']) if data.get('dhcpv6-rebind-received') else '0'
                temp['dhcpv6_reconfig_msgs_sent_by_the_relay_agent'] = str(data['dhcpv6-reconfigure-sent']) if data.get('dhcpv6-reconfigure-sent') else '0'
                temp['dhcpv6_relay_fwd_msgs_sent_by_the_relay_agent'] = str(data['dhcpv6-relay-forw-sent']) if data.get('dhcpv6-relay-forw-sent') else '0'
                temp['dhcpv6_relay_reply_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-relay-reply-received']) if data.get('dhcpv6-relay-reply-received') else '0'
                temp['dhcpv6_release_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-release-received']) if data.get('dhcpv6-release-received') else '0'
                temp['dhcpv6_reply_msgs_sent_by_the_relay_agent'] = str(data['dhcpv6-reply-sent']) if data.get('dhcpv6-reply-sent') else '0'
                temp['dhcpv6_rqst_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-request-received']) if data.get('dhcpv6-request-received') else '0'
                temp['dhcpv6_solic_msgs_rcvd_by_the_relay_agent'] = str(data['dhcpv6-solicit-received']) if data.get('dhcpv6-solicit-received') else '0'
                temp['number_of_dhcpv6_pkts_drpd_due_to_an_inv_opcode'] = str(data['invalid-opcode']) if data.get('invalid-opcode') else '0'
                temp['number_of_dhcpv6_pkts_drpd_due_to_an_inv_option'] = str(data['invalid-options']) if data.get('invalid-options') else '0'
                temp['total_nbr_of_dhcpv6_pkts_drpd_by_the_relay_agent'] = str(data['total-dropped']) if data.get('total-dropped') else '0'
            retval.append(temp)
    st.debug(retval)
    return retval

def config_dhcp_snooping(dut, **kwargs):
    """
    author: Raghukumar Rampur
    :param addr_family:
    :type addr_family:
    :param vlanID:
    :type vlanID:
    :param interface:
    :type interface:

    usage:
    config_dhcp_snooping(dut,enable_global='yes')
    config_dhcp_snooping(dut,addr_family='ipv6',enable_global='yes')
    config_dhcp_snooping(dut,enable_local='yes',vlan_list=['10-20'])
    config_dhcp_snooping(dut,addr_family='ipv6',enable_local='yes',vlan_list=['10'])
    config_dhcp_snooping(dut,addr_family='ipv6',enable_trust_port='yes',interface='Ethernet46')
    config_dhcp_snooping(dut,enable_trust_port='yes',interface=['Ethernet46','Ethernet0-12','Ethernet48'])
    config_dhcp_snooping(dut,enable_mac_verify='yes')

    """
    cli_type = st.get_ui_type(dut, **kwargs)
    addr_family = kwargs.pop('addr_family', 'ip')
    enable_global = kwargs.pop('enable_global', 'no')
    enable_local  = kwargs.pop('enable_local', 'no')
    enable_feature = kwargs.pop('enable_feature', 'no')
    enable_mac_verify  = kwargs.pop('enable_mac_verify', 'no')
    enable_trust_port  = kwargs.pop('enable_trust_port', 'no')
    config = kwargs.pop('config', 'yes')
    skip_error_check = kwargs.pop('skip_error_check', False)

    if addr_family == 'ipv4':
        addr_family ='ip'

    cli_type='klish' if cli_type in get_supported_ui_type_list() and 'intf_list' in kwargs or 'vlan_list' in kwargs else cli_type
    if cli_type in get_supported_ui_type_list():
        if enable_global.lower() == "yes":
            cfgmode = False if config != 'yes' else True
            if addr_family == 'ip':
                snooping_obj =umf_snooping.DhcpSnooping(Dhcpv4AdminEnable=cfgmode)
                target_attr =snooping_obj.Dhcpv4AdminEnable
            else:
                snooping_obj =umf_snooping.DhcpSnooping(Dhcpv6AdminEnable=cfgmode)
                target_attr =snooping_obj.Dhcpv6AdminEnable

        if enable_mac_verify == "yes":
            cfgmode = False if config != 'yes' else True
            if addr_family == 'ip':
                snooping_obj =umf_snooping.DhcpSnooping(Dhcpv4VerifyMacAddress=cfgmode)
                target_attr =snooping_obj.Dhcpv4VerifyMacAddress
            else:
                snooping_obj =umf_snooping.DhcpSnooping(Dhcpv6VerifyMacAddress=cfgmode)
                target_attr =snooping_obj.Dhcpv6VerifyMacAddress

        if config == 'yes':
            result = snooping_obj.configure(dut,cli_type=cli_type)

        if config == 'no':
            result = snooping_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)

        if not result.ok():
                st.log('test_step_failed: Config dhcp snooping {}'.format(result.data))
                return False
        return True

    cmd =''
    if cli_type == 'click':
        cfgmode = 'disable' if config != 'yes' else 'enable'

        if addr_family == 'ip':
            addr_family ='dhcpv4'
        else:
            addr_family ='dhcpv6'

        if enable_feature.lower() == "yes":
            #cmd += "sudo config dhcp-snooping feature\n"
            st.log('cmd sudo config dhcp-snooping feature is removed ')
        if enable_global.lower() == "yes":
            cmd +=" config ip dhcp-snooping {} {}\n".format(cfgmode,addr_family)
        if enable_local.lower() == "yes":
            if 'vlan_list' in kwargs:
                cmd +=" config ip dhcp-snooping vlan {} {} {}\n".format(cfgmode,kwargs['vlan_list'],addr_family)

        if enable_mac_verify == "yes":
            cmd +=" config ip dhcp-snooping mac_verify {} {}\n".format(addr_family,cfgmode)

        if  enable_trust_port =='yes':
            mode = 'untrust' if config != 'yes' else 'trust'
            if 'intf_list' in kwargs:
                kwargs['intf_list'] = make_list(kwargs['intf_list'])
                for intf_item in kwargs['intf_list']:
                    cmd +=" config ip dhcp-snooping trust {} {} {}\n".format(intf_item,addr_family,mode)

        output =st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
        return output

    elif cli_type == "klish":
        cfgmode = 'no' if config != 'yes' else ''
        if enable_global.lower() == "yes":
            cmd += " {} {} dhcp snooping\n".format(cfgmode,addr_family)

        if enable_local.lower() == "yes":
            if 'vlan_list' in kwargs:
                kwargs['vlan_list'] = make_list(kwargs['vlan_list'])
                for vlan in kwargs['vlan_list']:
                    cmd += " {} {} dhcp snooping vlan {}\n".format(cfgmode,addr_family,vlan)

        if enable_mac_verify == "yes":
            cmd += " {} {} dhcp snooping verify mac-address\n".format(cfgmode,addr_family)

        if  enable_trust_port =='yes':
            if 'intf_list' in kwargs:
                kwargs['intf_list'] = make_list(kwargs['intf_list'])
                port_hash_list = segregate_intf_list_type(intf=kwargs['intf_list'], range_format=True)
                interface = port_hash_list['intf_list_all']
                for intf_item in interface:
                    if not is_a_single_intf(intf_item):
                        cmd += " interface range {}\n".format(intf_item)
                    else:
                        interface_data = get_interface_number_from_name(intf_item)
                        cmd += " interface {} {}\n".format(interface_data['type'], interface_data['number'])
                    cmd += " {} {} dhcp snooping trust\n".format(cfgmode,addr_family)
                    cmd += "exit\n"
        output =st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
        return output
    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        if 'vlan_list' in kwargs:
            vlan_list = [kwargs['vlan_list']] if type(kwargs['vlan_list']) is str else kwargs['vlan_list']
        if config.lower() == "yes":
            if enable_global.lower() == "yes":
                if addr_family == 'ip':
                    rest_url = rest_urls['dhcp_snooping_enable_disable_global']
                    payload ={"openconfig-dhcp-snooping:dhcpv4-admin-enable":bool(1)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                elif addr_family == 'ipv6':
                    rest_url = rest_urls['dhcp_snoopingv6_enable_disable_global']
                    payload ={"openconfig-dhcp-snooping:dhcpv6-admin-enable":bool(1)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

            if enable_local.lower() == "yes":
                if addr_family == 'ip':
                    if '-' in kwargs['vlan_list']:
                        vlans = kwargs['vlan_list'].split('-')
                        vlan_list = range(int(vlans[0]),int(vlans[-1])+1)
                    for each_vlan in vlan_list:
                        rest_url = rest_urls['dhcp_snooping_enable_disable_local'].format(each_vlan)
                        payload ={"sonic-vlan:dhcpv4_snooping_enable":"enable"}
                        config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

                elif addr_family == 'ipv6':
                    if '-' in kwargs['vlan_list']:
                        vlans = kwargs['vlan_list'].split('-')
                        vlan_list = range(int(vlans[0]),int(vlans[-1])+1)
                    for each_vlan in vlan_list:
                        rest_url = rest_urls['dhcp_snoopingv6_enable_disable_local'].format(each_vlan)
                        payload ={"sonic-vlan:dhcpv6_snooping_enable":"enable"}
                        config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

            if enable_mac_verify == "yes":
                if addr_family == 'ip':
                    rest_url = rest_urls['dhcp_snooping_enable_disable_mac_verify']
                    payload ={"openconfig-dhcp-snooping:dhcpv4-verify-mac-address":bool(1)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                elif addr_family == 'ipv6':
                    rest_url = rest_urls['dhcp_snoopingv6_enable_disable_mac_verify']
                    payload ={"openconfig-dhcp-snooping:dhcpv6-verify-mac-address":bool(1)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

            if  enable_trust_port =='yes':
                if 'intf_list' in kwargs:
                    kwargs['intf_list'] = make_list(kwargs['intf_list'])
                    for intf_item in kwargs['intf_list']:
                        index = get_subinterface_index(dut, intf_item)
                        if not index:
                            st.error("Failed to get index for interface: {}".format(intf_item))
                            index = 0
                        interface_name = get_phy_port(intf_item)
                        st.banner(interface_name)
                        if addr_family == 'ip':
                            rest_url = rest_urls['dhcp_snooping_enable_disable_trustport'].format(interface_name)
                            payload = {"openconfig-interfaces:dhcpv4-snooping-trust": {"config": {"dhcpv4-snooping-trust": "ENABLE"}}}
                            config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                        elif addr_family == 'ipv6':
                            rest_url = rest_urls['dhcp_snoopingv6_enable_disable_trustport'].format(interface_name)
                            payload = {"openconfig-interfaces:dhcpv6-snooping-trust": {"config": {"dhcpv6-snooping-trust": "ENABLE"}}}
                            config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

        if config.lower() == "no":
            if enable_global.lower() == "yes":
                if addr_family == 'ip':
                    rest_url = rest_urls['dhcp_snooping_enable_disable_global']
                    payload ={"openconfig-dhcp-snooping:dhcpv4-admin-enable":bool(0)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                elif addr_family == 'ipv6':
                    rest_url = rest_urls['dhcp_snoopingv6_enable_disable_global']
                    payload ={"openconfig-dhcp-snooping:dhcpv6-admin-enable":bool(0)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

            if enable_local.lower() == "yes":
                if addr_family == 'ip':
                    if '-' in kwargs['vlan_list']:
                        vlans = kwargs['vlan_list'].split('-')
                        vlan_list = range(int(vlans[0]),int(vlans[-1])+1)
                    for each_vlan in vlan_list:
                        rest_url = rest_urls['dhcp_snooping_enable_disable_local'].format(each_vlan)
                        payload ={"sonic-vlan:dhcpv4_snooping_enable":"disable"}
                        config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                elif addr_family == 'ipv6':
                    if '-' in kwargs['vlan_list']:
                        vlans = kwargs['vlan_list'].split('-')
                        vlan_list = range(int(vlans[0]),int(vlans[-1])+1)
                    for each_vlan in vlan_list:
                        rest_url = rest_urls['dhcp_snoopingv6_enable_disable_local'].format(each_vlan)
                        payload ={"sonic-vlan:dhcpv6_snooping_enable":"disable"}
                        config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

            if enable_mac_verify == "yes":
                if addr_family == 'ip':
                    rest_url = rest_urls['dhcp_snooping_enable_disable_mac_verify']
                    payload ={"openconfig-dhcp-snooping:dhcpv4-verify-mac-address":bool(0)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                elif addr_family == 'ipv6':
                    rest_url = rest_urls['dhcp_snoopingv6_enable_disable_mac_verify']
                    payload ={"openconfig-dhcp-snooping:dhcpv6-verify-mac-address":bool(0)}
                    config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

            if  enable_trust_port =='yes':
                if 'intf_list' in kwargs:
                    kwargs['intf_list'] = make_list(kwargs['intf_list'])
                    for intf_item in kwargs['intf_list']:
                        index = get_subinterface_index(dut, intf_item)
                        if not index:
                            st.error("Failed to get index for interface: {}".format(intf_item))
                            index = 0
                        interface_name = get_phy_port(intf_item)
                        st.banner(interface_name)
                        if addr_family == 'ip':
                            rest_url = rest_urls['dhcp_snooping_enable_disable_trustport'].format(interface_name)
                            payload = {"openconfig-interfaces:dhcpv4-snooping-trust": {"config": {"dhcpv4-snooping-trust": "DISABLE"}}}
                            config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)
                        elif addr_family == 'ipv6':
                            rest_url = rest_urls['dhcp_snoopingv6_enable_disable_trustport'].format(interface_name)
                            payload = {"openconfig-interfaces:dhcpv6-snooping-trust": {"config": {"dhcpv6-snooping-trust": "DISABLE"}}}
                            config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def clear_dhcp_snooping_binding(dut, **kwargs):
    """
    author: Raghukumar Rampur
    :param addr_family:
    :type addr_family:

    usage:
    clear_dhcp_snooping_binding(dut,addr_family='ip')
    clear_dhcp_snooping_binding(dut,addr_family='ipv6')

    """
    addr_family = kwargs.pop('addr_family', 'ip')
    skip_error_check = kwargs.pop('skip_error_check', False)
    #del_specific_bindingEntry = kwargs.pop('del_specific_bindingEntry', 'no')
    ip_addr = kwargs.pop('ip_addr', None)
    mac_addr = kwargs.pop('mac_addr', None)
    vlan = kwargs.pop('vlan', None)
    intf = kwargs.pop('intf', None)
    if addr_family == 'ipv4':
        addr_family ='ip'

    cli_type = st.get_ui_type(dut,**kwargs)
    #cli_type='klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    cmd =''
    if cli_type in get_supported_ui_type_list():
        service = YangRpcService()
        rpc = umf_snooping_rpc.ClearDhcpSnoopingBindingRpc() if addr_family == 'ip' else umf_snooping_rpc.ClearDhcpv6SnoopingBindingRpc()
        rpc.Input.clear_type='V4_ALL' if addr_family == 'ip' else 'V6_ALL'
        '''
        rpc.Input.interface = ''
        rpc.Input.vlan = ''
        rpc.Input.ip = ''
        rpc.Input.mac_address = ''
        '''
        result = service.execute(dut, rpc, timeout=60, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Clear DHCP Snooping Bindings failed: {}'.format(result.data))
            return False

        return True

    elif cli_type == 'click':
        cmd += " sonic-clear {} dhcp-snooping all\n".format(addr_family)
        output =st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
        return output

    elif cli_type == "klish":
        if ip_addr and mac_addr and vlan and intf:
            cmd += " clear {} dhcp snooping binding {} {} Vlan {} {}".format(addr_family, ip_addr, mac_addr, vlan, intf)
        else:
            cmd += " clear {} dhcp snooping binding\n".format(addr_family)
        output =st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
        return output

    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def create_dhcp_snooping_binding(dut, ip_addr_list, mac_addr_list, vlan_list, intf_list, **kwargs):
    """
    author: Raghukumar Rampur
    :param addr_family:
    :type addr_family:
    :param vlanID:
    :type vlanID:
    :param interface:
    :type interface:
    :param ip_addr:
    :type ip_addr:
    :param mac_addr:
    :type mac_addr:

    usage:
    create_dhcp_snooping_binding(dut1,ip_addr_list='20.20.20.1',mac_addr_list='00:10:94:02:01:05',vlan_list='33',intf_list='Ethernet46')
    create_dhcp_snooping_binding(dut1,ip_addr_list=['20.20.20.1'],mac_addr_list=['00:10:94:02:01:05'],vlan_list=['33'],intf_list='Ethernet46')

    """

    addr_family = kwargs.pop('addr_family', 'ip')
    config = kwargs.pop('config', 'yes')
    skip_error_check = kwargs.pop('skip_error_check', False)

    if addr_family == 'ipv4':
        addr_family ='ip'

    cli_type = st.get_ui_type(dut,**kwargs)

    cmd =''
    intf_list = make_list(intf_list)
    vlan_list = make_list(vlan_list)
    ip_addr_list = make_list(ip_addr_list)
    mac_addr_list = make_list(mac_addr_list)

    cli_type='klish' if cli_type in get_supported_ui_type_list() else cli_type
    if cli_type in get_supported_ui_type_list():
        if addr_family == 'ip':
            addr_family ="ipv4"

        if len(ip_addr_list) != len(mac_addr_list) or len(vlan_list) != len(mac_addr_list) or len(intf_list) != len(mac_addr_list):
            st.error('Please check ip_addr list and mac_addr list, number of entries should be same')
            return False

        for intf,vlan,ipaddr,macaddr in zip(intf_list,vlan_list,ip_addr_list,mac_addr_list):
            #vlan_intf="Vlan{}".format(vlan)
            snooping_obj =umf_snooping.Entry(Mac=macaddr, Iptype=addr_family, Vlan=vlan, Interface=intf, Ip=ipaddr)

        if config == 'yes':
            result = snooping_obj.configure(dut,cli_type=cli_type)

        if config == 'no':
            result = snooping_obj.unConfigure(dut, cli_type=cli_type)

        if not result.ok():
                st.log('test_step_failed: Config dhcp snooping {}'.format(result.data))
                return False
        return True



    if cli_type == 'click':
        cfgmode = 'del' if config != 'yes' else 'add'

        if len(ip_addr_list) != len(mac_addr_list) or len(vlan_list) != len(mac_addr_list) or len(intf_list) != len(mac_addr_list):
            st.error('Please check ip_addr list and mac_addr list, number of entries should be same')
            return False

        for intf,vlan,ipaddr,macaddr in zip(intf_list,vlan_list,ip_addr_list,mac_addr_list):
            cmd += " config ip dhcp-snooping static {} {} {} {} {}\n".format(cfgmode,macaddr,vlan,intf,ipaddr)

        output =st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
        return output

    elif cli_type == "klish":
        cfgmode = 'no' if config != 'yes' else ''

        if len(ip_addr_list) != len(mac_addr_list) or len(vlan_list) != len(mac_addr_list) or len(intf_list) != len(mac_addr_list):
            st.error('Please check ip_addr list and mac_addr list, number of entries should be same')
            return False

        for intf,vlan,ipaddr,macaddr in zip(intf_list,vlan_list,ip_addr_list,mac_addr_list):
            cmd += "{} {} source binding {} {} Vlan {} {}\n".format(cfgmode,addr_family,ipaddr, macaddr, vlan, intf)

        output =st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
        return output

    elif cli_type in ['rest-patch','rest-put']:
        rest_urls = st.get_datastore(dut,'rest_urls')
        if len(ip_addr_list) != len(mac_addr_list) or len(vlan_list) != len(mac_addr_list) or len(intf_list) != len(mac_addr_list):
            st.error('Please check ip_addr list and mac_addr list, number of entries should be same')
            return False

        if addr_family == 'ip':
            addr_family ="ipv4"

        if config.lower() == "yes":
            for intf,vlan,ipaddr,macaddr in zip(intf_list,vlan_list,ip_addr_list,mac_addr_list):
                vlan_intf="Vlan{}".format(vlan)
                rest_url = rest_urls['dhcp_snooping_config_staticbinding']
                payload ={"sonic-dhcp-snooping:DHCP_SNOOPING_STATIC_BINDING": {"DHCP_SNOOPING_STATIC_BINDING_LIST": [{"interface": intf, "ip": ipaddr, "mac": macaddr,"vlan": vlan_intf, "iptype": addr_family}]}}
                config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=payload)

        if config.lower() == "no":
            for intf,vlan,ipaddr,macaddr in zip(intf_list,vlan_list,ip_addr_list,mac_addr_list):
                rest_url = rest_urls['dhcp_snooping_delete_staticbinding'].format(macaddr,addr_family)
                if not delete_rest(dut, rest_url=rest_url, timeout=100):
                    st.error("Failed to delete static binding entry ")
                    return False

    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def verify_dhcp_snooping_binding(dut, **kwargs):
    """
    Author:Raghukumar Rampur

    :param total_bindings:
    :type total_bindings
    :param tentative_bindings:
    :type tentative_bindings


    usage:
     verify_dhcp_snooping_binding(dut1,total_bindings ='1024',binding_type_list =['STATIC','DYNAMIC'],ip_addr_list=['20.1.1.1','30.1.2.3'])
     verify_dhcp_snooping_binding(dut1,total_bindings ='1024',interface_list=['Ethernet9','Ethernet1'])
    """


    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    addr_family = kwargs.pop('addr_family', 'ip')
    if addr_family == 'ipv4':
        addr_family ='ip'

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        st.banner('Verifying dhcp_snooping_binding table ')
        if addr_family == 'ip':
            dhcp_snooping_attr ={
                'dynamic_bindings' : ['V4DynamicCount',kwargs.get('dynamic_bindings', None)],
                'static_bindings' : ['V4StaticCount',kwargs.get('static_bindings', None)],
                'tentative_bindings' : ['V4TentativeCount', kwargs.get('tentative_bindings', None)],
            }
        else:
            dhcp_snooping_attr ={
                'dynamic_bindings' : ['V6DynamicCount', kwargs.get('dynamic_bindings', None)],
                'static_bindings' : ['V6StaticCount', kwargs.get('static_bindings', None)],
                'tentative_bindings' : ['V6TentativeCount', kwargs.get('tentative_bindings', None)],
            }

        if 'mac_addr_list' not in kwargs:
            snooping_obj =umf_snooping.DhcpSnoopingBinding()
            st.banner(dhcp_snooping_attr)
            for key, attr_value in  dhcp_snooping_attr.items():
                if key in kwargs and attr_value[1] is not None:
                    setattr(snooping_obj, attr_value[0], attr_value[1])
            result = snooping_obj.verify(dut,match_subset=True, query_param=query_param_obj,cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Verification dhcp-snooping {}'.format(result.data))
                return False
        else:
            if addr_family == 'ip':
                addr_family ='ipv4'
            snooping_obj_count =umf_snooping.DhcpSnoopingBinding()
            for index, mac in enumerate(kwargs['mac_addr_list']):
                snooping_obj =umf_snooping.DhcpSnoopingBindingList(Mac=mac,Iptype=addr_family,DhcpSnoopingBinding=snooping_obj_count)

                if 'vlan_list' in kwargs: dhcp_snooping_attr['vlan_list'] = ['Vlan', kwargs['vlan_list'][index]]
                if 'binding_type_list' in kwargs: dhcp_snooping_attr['binding_type_list'] = ['Type', kwargs['binding_type_list'][index]]
                if 'interface_list' in kwargs: dhcp_snooping_attr['interface_list'] = ['Intf', kwargs['interface_list'][index]]
                if 'ip_addr_list' in kwargs: dhcp_snooping_attr['ip_addr_list'] = ['Ipaddress', kwargs['ip_addr_list'][index]]

                st.banner(dhcp_snooping_attr)
                for key, attr_value in  dhcp_snooping_attr.items():
                    if key in kwargs and attr_value[1] is not None:
                        setattr(snooping_obj, attr_value[0], attr_value[1])
            st.log('***IETF_JSON***: {}'.format(snooping_obj.get_ietf_json()))
            result = snooping_obj.verify(dut,match_subset=True, query_param=query_param_obj,cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Verification dhcp-snooping {}'.format(result.data))
                return False
        return True

    elif cli_type == 'click':
        cmd = "show {} dhcp-snooping binding".format(addr_family)
        parsed_output = st.show(dut,cmd,type=cli_type)

    elif cli_type == 'klish':
        cmd = "show {} dhcp snooping binding".format(addr_family)
        parsed_output = st.show(dut,cmd,type=cli_type)

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        dynamic_bind =''
        tentative_bind = ''
        static_bind = ''
        vlan_list =[]
        mac_list =[]
        ipaddr_list =[]
        intf_list =[]
        leasetime_list =[]
        binding_type_list =[]
        multi_var =[]

        rest_url = rest_urls['show_dhcp_snooping_binding']
        out = get_rest(dut, rest_url=rest_url)
        if addr_family == 'ip':
            static_bind =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-count']['state']['v4-static-count'])
            tentative_bind =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-count']['state']['v4-tentative-count'])
            dynamic_bind =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-count']['state']['v4-dynamic-count'])

            if 'dhcp-snooping-binding-entry-list' in out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']:
                len_entries =len(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'])
                for i in range(len_entries):
                    addr_type =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['iptype'])
                    if addr_type =='ipv4':
                        mac =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['mac'])
                        ipaddr =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['ipaddress'])
                        vlan =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['vlan'])
                        intf =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['intf'])
                        binding =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['type'])
                        if 'lease-time' in out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']:
                            leasetime =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['lease-time'])
                        else:
                            leasetime ='NA'
                        mac_list.append(mac);ipaddr_list.append(ipaddr);vlan_list.append(vlan);intf_list.append(intf);binding_type_list.append(binding);leasetime_list.append(leasetime)

        elif addr_family == 'ipv6':
            static_bind =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-count']['state']['v6-static-count'])
            tentative_bind =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-count']['state']['v6-tentative-count'])
            dynamic_bind =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-count']['state']['v6-dynamic-count'])

            if 'dhcp-snooping-binding-entry-list' in out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']:
                len_entries =len(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'])
                for i in range(len_entries):
                    addr_type =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['iptype'])
                    if addr_type =='ipv6':
                        mac =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['mac'])
                        ipaddr =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['ipaddress'])
                        vlan =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['vlan'])
                        intf =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['intf'])
                        binding =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['type'])
                        if 'lease-time' in out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']:
                            leasetime =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping-binding']['dhcp-snooping-binding-entry-list']['dhcp-snooping-binding-list'][i]['state']['lease-time'])
                        else:
                            leasetime ='NA'
                        mac_list.append(mac);ipaddr_list.append(ipaddr);vlan_list.append(vlan);intf_list.append(intf);binding_type_list.append(binding);leasetime_list.append(leasetime)

        single_var = {'tentative_bindings':tentative_bind ,'dynamic_bindings':dynamic_bind ,'vlan_list':vlan_list, 'lease_time_list':leasetime_list, 'ip_addr_list':ipaddr_list, 'static_bindings':static_bind, 'interface_list':intf_list, 'binding_type_list':binding_type_list,'mac_addr_list':mac_list}
        multi_var.append(single_var)

        parsed_output =multi_var

    if cli_type in ['click', 'klish','rest-patch','rest-put']:
        if parsed_output:
            parsed_output[0]['vlan_list'] =natsorted(parsed_output[0]['vlan_list'])


    st.banner(parsed_output)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return parsed_output
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(parsed_output, None, match)
        if not entries:
            st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each],parsed_output[0][each]))
            return False
    return True


def verify_dhcp_snooping(dut, **kwargs):
    """
    Author:Raghukumar Rampur

    :param total_bindings:
    :type total_bindings
    :param tentative_bindings:
    :type tentative_bindings


    usage:
     verify_dhcp_snooping(dut1,snooping_state ='Enabled',  trusted_port_state =['Yes','No'],vlan_enabled=['100,2'])
     verify_dhcp_snooping(dut1,snooping_state ='Disabled', interface_list=['Ethernet9','Ethernet1'],mac_verification_state ='Enabled')
    """


    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    addr_family = kwargs.pop('addr_family', 'ip')

    if addr_family == 'ipv4':
        addr_family ='ip'

    if cli_type in get_supported_ui_type_list():
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        st.banner('Verifying dhcp_snooping table ')
        config =None
        mac_config =None
        snooping_obj =umf_snooping.DhcpSnooping()
        if 'snooping_state' in kwargs:
            if kwargs['snooping_state'] =='Enabled':
               config =True
            else:
                config =False

        if 'mac_verification_state' in kwargs:
            if kwargs['mac_verification_state'] =='Enabled':
               mac_config =True
            else:
                mac_config =False

        if addr_family == 'ip':
            dhcp_snooping_attr ={
                'snooping_state' : ['Dhcpv4AdminEnable',config],
                'mac_verification_state' : ['Dhcpv4VerifyMacAddress',mac_config],
                'interface_list' : ['Dhcpv4TrustedIntf', kwargs.get('interface_list', None)],
                'vlan_enabled' : ['Dhcpv4SnoopingVlan', kwargs.get('vlan_enabled', None)],
            }

        else:
            dhcp_snooping_attr ={
                'snooping_state' : ['Dhcpv6AdminEnable', config],
                'mac_verification_state' : ['Dhcpv6VerifyMacAddress', mac_config],
                'interface_list' : ['Dhcpv6TrustedIntf', kwargs.get('interface_list', None)],
                'vlan_enabled' : ['Dhcp6SnoopingVlan', kwargs.get('vlan_enabled', None)],
            }
        st.banner(dhcp_snooping_attr)
        for key, attr_value in  dhcp_snooping_attr.items():
            if key in kwargs and attr_value[1] is not None:
                setattr(snooping_obj, attr_value[0], attr_value[1])
        st.log('***IETF_JSON***: {}'.format(snooping_obj.get_ietf_json()))
        result = snooping_obj.verify(dut,match_subset=True, query_param=query_param_obj,cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Verification dhcp-snooping {}'.format(result.data))
            return False
        return True

    elif cli_type == 'click':
        cmd = "show {} dhcp-snooping".format(addr_family)
        parsed_output = st.show(dut,cmd,type=cli_type)

    elif cli_type == 'klish':
        if 'vlan_enabled' in kwargs:
            kwargs['vlan_enabled'] = get_range_from_sequence(val=kwargs['vlan_enabled'])
        cmd = "show {} dhcp snooping".format(addr_family)
        parsed_output = st.show(dut,cmd,type=cli_type)

    elif cli_type in ['rest-patch', 'rest-put']:
        rest_urls = st.get_datastore(dut, 'rest_urls')
        snooping_state_v4 =''
        snooping_state_v6 =''
        mac_verification_state_v4 = ''
        mac_verification_state_v6 = ''
        vlan_enabled_v4 =[]
        vlan_enabled_v6 =[]
        intf_list_v4 =[]
        intf_list_v6 =[]
        multi_var =[]

        rest_url = rest_urls['show_dhcp_snooping_config']
        out = get_rest(dut, rest_url=rest_url)
        if addr_family == 'ip':
            snooping_state_v4 =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']['dhcpv4-admin-enable'])
            mac_verification_state_v4 =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']['dhcpv4-verify-mac-address'])
            if snooping_state_v4 == 'True':
                snooping_state_v4 ='Enabled'
            else:
                snooping_state_v4 ='Disabled'

            if mac_verification_state_v4 == 'True':
                mac_verification_state_v4 ='Enabled'
            else:
                mac_verification_state_v4 ='Disabled'

            if 'dhcpv4-snooping-vlan' in out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']:
                vlan_enabled =(out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']['dhcpv4-snooping-vlan'])
                vlan_enabled_v4 =ast.literal_eval(json.dumps(vlan_enabled))

            if 'dhcpv4-trusted-intf' in out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']:
                intf_list =(out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']['dhcpv4-trusted-intf'])
                intf_list_v4 =ast.literal_eval(json.dumps(intf_list))

        if addr_family == 'ipv6':
            snooping_state_v6 =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']['dhcpv6-admin-enable'])
            mac_verification_state_v6 =str(out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']['dhcpv6-verify-mac-address'])
            if snooping_state_v6 == 'True':
                snooping_state_v6 ='Enabled'
            else:
                snooping_state_v6 ='Disabled'

            if mac_verification_state_v6 == 'True':
                mac_verification_state_v6 ='Enabled'
            else:
                mac_verification_state_v6 ='Disabled'

            if 'dhcpv6-snooping-vlan' in out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']:
                vlan_enabled =(out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']['dhcpv6-snooping-vlan'])
                vlan_enabled_v6 =ast.literal_eval(json.dumps(vlan_enabled))

            if 'dhcpv6-trusted-intf' in out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']:
                intf_list =(out['output']['openconfig-dhcp-snooping:dhcp-snooping']['state']['dhcpv6-trusted-intf'])
                intf_list_v6 =ast.literal_eval(json.dumps(intf_list))

        if addr_family == 'ip':
            single_var = {'snooping_state': snooping_state_v4,'interface_list': intf_list_v4,'vlan_enabled' :vlan_enabled_v4, 'mac_verification_state': mac_verification_state_v4}
        else:
            single_var = {'snooping_state': snooping_state_v6,'interface_list': intf_list_v6,'vlan_enabled' :vlan_enabled_v6, 'mac_verification_state': mac_verification_state_v6}
        multi_var.append(single_var)

        parsed_output =multi_var
    if cli_type in ['click', 'klish']:
        parsed_output[0]['interface_list'] =str(parsed_output[0]['interface_list'].rstrip())
        parsed_output[0]['interface_list'] =parsed_output[0]['interface_list'].split(' ')
        parsed_output[0]['vlan_enabled'] =str(parsed_output[0]['vlan_enabled'].rstrip())
        parsed_output[0]['vlan_enabled'] =parsed_output[0]['vlan_enabled'].split(' ')
    if cli_type in ['click', 'klish','rest-patch','rest-put']:
        parsed_output[0]['vlan_enabled'] =natsorted(parsed_output[0]['vlan_enabled'])
    st.banner(parsed_output)
    if len(parsed_output) == 0:
        st.error("OUTPUT is Empty")
        return False

    if 'return_output' in kwargs:
        return parsed_output
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(parsed_output, None, match)
        if not entries:
            st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each],parsed_output[0][each]))
            return False
    return True

def show_dhcp_snooping_statistics(dut, **kwargs):
    """
    Author:Raghukumar Rampur

    :param :dut:
    :param :cli_type:
    :param :skip_error:


    usage:
    show_dhcp_snooping_statistics(dut1)
    show_dhcp_snooping_statistics(dut1,addr_family='ipv6')
    """


    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    cli_type='klish' if cli_type in get_supported_ui_type_list() else cli_type

    addr_family = kwargs.pop('addr_family', 'ip')
    if addr_family == 'ipv4':
        addr_family ='ip'

    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'

    if cli_type == 'click':
        cmd = "show {} dhcp-snooping statistics detail".format(addr_family)
        return st.show(dut,cmd,type=cli_type)

    elif cli_type == 'klish':
        cmd = "show {} dhcp snooping statistics detail".format(addr_family)
        return st.show(dut,cmd,type=cli_type)

    return None

def verify_dhcp_snooping_statistics_detail(dut, **kwargs):
    """
    API to verify the DHCP snooping statistics detail
    :param dut:
    :param kwargs:
    Kwargs contains the key value pair to verify, values of each key can be <exact number> for exact match,
    "non-zero" for matching of positive non zero values
    :return:

    usage:
    verify_dhcp_snooping_statistics_detail(data.dut1,addr_family='ip',binding_entries_added=0,dhcp_msg_intercepted=0,dhcp_msg_processed=0)
    verify_dhcp_snooping_statistics_detail(data.dut1,addr_family='ipv6',binding_entries_added=0,dhcp_msg_intercepted=0,dhcp_msg_processed=0)

    """
    addr_family = kwargs.pop("addr_family", "ip")
    cli_type = st.get_ui_type(dut, **kwargs)
    cli_type='klish' if cli_type in get_supported_ui_type_list() + ['rest-patch', 'rest-put'] else cli_type
    if kwargs.get("cli_type"):
        del kwargs["cli_type"]
    if cli_type == 'klish':
        cmd = "show {} dhcp snooping statistics detail ".format(addr_family)
        parsed_output = st.show(dut,cmd,type=cli_type)
    st.banner(parsed_output)

    if 'return_output' in kwargs:
        return parsed_output
    for each in kwargs.keys():
        match = {each: kwargs[each]}
        entries = filter_and_select(parsed_output, None, match)
        if not entries:
            st.error("Match not found for {}:   Expected - {} Actual - {} ".format(each, kwargs[each],parsed_output[0][each]))
            return False
    return True

def clear_dhcp_snooping_statistics(dut, **kwargs):
    """
    author: Raghukumar Rampur
    :param addr_family:
    :type addr_family:

    usage:
    clear_dhcp_snooping_statistics(dut,addr_family='ip')
    clear_dhcp_snooping_statistics(dut,addr_family='ipv6')
    clear_dhcp_snooping_statistics(dut,addr_family='ip',intf='Eth10')
    clear_dhcp_snooping_statistics(dut,addr_family='ipv6',intf='Eth10')
    """
    addr_family = kwargs.pop('addr_family', 'ip')
    skip_error_check = kwargs.pop('skip_error_check', False)
    if addr_family == 'ipv4':
        addr_family ='ip'

    cli_type = st.get_ui_type(dut,**kwargs)
    intf = kwargs.pop('intf', None)
    if cli_type in ['rest-patch', 'rest-put','click']: cli_type = 'klish'
    if cli_type in get_supported_ui_type_list():
        service = YangRpcService()
        if intf is None:
            rpc = umf_snooping_rpc.ClearDhcpSnoopingStatisticsDetailRpc() if addr_family == 'ip' else umf_snooping_rpc.ClearDhcpv6SnoopingStatisticsDetailRpc()
        else:
            rpc = umf_snooping_rpc.ClearDhcpSnoopingStatisticsRpc() if addr_family == 'ip' else umf_snooping_rpc.ClearDhcpv6SnoopingStatisticsRpc()
            rpc.Input.interface = intf
        result = service.execute(dut, rpc, timeout=60, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Clear DHCP Snooping Stats failed: {}'.format(result.data))
            return False

        return True

    elif cli_type == "klish":
        cmd =''
        if intf:
            cmd += " clear {} dhcp snooping statistics {}\n".format(addr_family,intf)
        else:
            cmd += " clear {} dhcp snooping statistics detail\n".format(addr_family)
        output =st.config(dut, cmd, skip_error_check=skip_error_check, type=cli_type)
        return output

    else:
        st.log("Unsupported CLI TYPE - {}".format(cli_type))
        return False

def dhcp_relay_circuitID_config(dut, **kwargs):
    """
    API for DHCP relay circuit ID configuration
    Author Raghukumar Rampur
    :param dut:
    :param kwargs:
    :return:
    usage:
    dhcp_relay.dhcp_relay_circuitID_config(vars.D2,interface=data.vlan1,sub_option='%h:%p',circuitID='no')
    dhcp_relay.dhcp_relay_circuitID_config(vars.D2,interface=data.vlan1,sub_option='%h:%p')
    dhcp_relay.dhcp_relay_circuitID_config(vars.D2,interface=data.vlan1,sub_option='%i')
    dhcp_relay.dhcp_relay_circuitID_config(vars.D2,interface=data.vlan1,sub_option='%p')

    """
    cli_type = st.get_ui_type(dut, **kwargs)
    interface = kwargs.get("interface", None)
    ip_family = kwargs.get("ip_family", "ipv4")
    skip_error_check = kwargs.get("skip_error_check", False)
    circuitID = kwargs.get("circuitID","yes")

    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    if not interface:
        st.error("Required key 'interface' is not passed")
        return False

    if cli_type in get_supported_ui_type_list():
        st.banner(kwargs)
        if ip_family == 'ipv4':
            if 'sub_option' in kwargs:
                circuitID_obj  = umf_relay.DhcpInterface(Id=interface, CircuitId=kwargs['sub_option'])
            else:
                kwargs['sub_option'] ='%p'
                circuitID_obj  = umf_relay.DhcpInterface(Id=interface, CircuitId=kwargs['sub_option'])
            result = circuitID_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config dhcp-relay circuit-ID {}'.format(result.data))
                return False
        else:
            st.error("Circuit Id is applicable for DHCPv4 packets only ")
            return False
        return True

    command = ""
    if cli_type == "click":
        if ip_family == "ipv4":
            if circuitID == 'yes':
                if 'sub_option' in kwargs:
                    command = "config interface ip dhcp-relay circuit-id {} {}\n".format(interface, kwargs['sub_option'])
                else:
                    kwargs['sub_option'] ='%p'
                    command = "config interface ip dhcp-relay circuit-id {} {}\n".format(interface, kwargs['sub_option'])
        if ip_family == "ipv6":
            st.error("Circuit Id is applicable for DHCPv4 packets only ")
            return False
        output =st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
        return output
    elif cli_type == "klish":
        pintf = get_interface_number_from_name(interface)
        command ="interface {} {}".format(pintf['type'], pintf['number'])
        if ip_family == "ipv4":
            if circuitID == 'yes':
                if 'sub_option' in kwargs:
                    command += "\n" +  " ip dhcp-relay circuit-id {}\n".format(kwargs['sub_option'])
            else:
                command += "\n" +  " no ip dhcp-relay circuit-id \n"
            command += "exit\n"
        if ip_family == "ipv6":
            st.error("Circuit Id is applicable for DHCPv4 packets only ")
            return False
        output =st.config(dut, command, skip_error_check=skip_error_check, type=cli_type)
        return output
    else:
        st.error("Unsupported CLI TYPE - {}".format(cli_type))
        return False

