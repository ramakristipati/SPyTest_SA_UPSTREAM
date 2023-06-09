#   OSPFv2 APIs
#   Author: Naveena Suvarna (naveen.suvarna@broadcom.com)

import re

from spytest import st

from apis.system.rest import config_rest, get_rest, delete_rest
from apis.system.reboot import config_save
from apis.system.basic  import get_system_status, get_attr_from_cfgdbjson, service_operations_by_systemctl
from apis.routing.ip_rest import get_subinterface_index
import apis.common.asic as asicapi

from utilities.utils import get_interface_number_from_name, is_a_single_intf
from utilities.common import integer_parse, is_basestring, filter_and_select, get_query_params, make_list
from utilities.utils import get_intf_short_name, get_supported_ui_type_list, convert_intf_name_to_component

try:
    import apis.yang.codegen.messages.interfaces.Interfaces as umf_intf
    import apis.yang.codegen.messages.network_instance as umf_ni
    from apis.yang.utils.common import Operation
#    from apis.yang.utils.query_param import QueryParam, YangDataType
except ImportError:
    pass


get_phy_port = lambda intf: re.search(r"(\S+)\.\d+", intf).group(1) if re.search(r"(\S+)\.\d+", intf) else intf

def force_cli_type_to_klish(cli_type):
    cli_type = "klish" if cli_type in get_supported_ui_type_list() else cli_type
    return cli_type


# ------------------ OSPF router command APIs -------------------------------------

def validate_config_result(command, result, error_match):

    if not is_basestring(result):
        st.error("Config Error: {}".format(command))
        st.error("Config Error: invalid result type {} - Returned {}".format(type(result), result))
        return False

    if len(result) == 0:
        return True

    if result.find("Unknown command") != -1:
        st.error("Config cmd: {}".format(command))
        st.error("Config Unknown command: {}".format(result))
        return False

    if result.find("Command incomplete") != -1:
        st.error("Config cmd: {}".format(command))
        st.error("Config Command incomplete: {}".format(result))
        return False

    if not isinstance(error_match, list):
        error_match = [error_match]

    if not isinstance(command, list):
        command = [command]

    error_match = error_match + ['%Error']

    for err_str in error_match:
        if len(err_str) and result.find(err_str) != -1:
            st.error("Config cmd: {}".format(command))
            st.error("Config Fail: matched config error string {} in {}".format(err_str, result))
            return False

    return True


def match_record_fields(record_entry, match={}):

    if not isinstance(record_entry, dict):
        st.log("OSPF - Record {} not a dictionary object".format(record_entry))
        return False

    match_found = True
    for match_key, match_value in match.items():
        if match_key not in record_entry.keys():
            match_found = False
            st.log("OSPF - Record {} does not have key {}.".format(record_entry, match_key))
            break
        else:
            if record_entry[match_key] != match_value:
                match_found = False
                st.log("OSPF - Record {} did not match {}:{}.".format(record_entry, match_key, match_value))
                break

    if match_found:
       st.log("OSPF - Record matched {}.".format(match))

    return match_found


def get_ospf_cli_type(dut, **kwargs):
    st_cli_type = st.get_ui_type(dut, **kwargs)
    if st_cli_type == 'klish':
       return 'klish'
    elif st_cli_type == 'click':
       return 'vtysh'
    elif st_cli_type in ["rest-patch", "rest-put"]+get_supported_ui_type_list():
        return st_cli_type
    else:
       return 'vtysh'


def check_if_klish_unconfig(dut, config, cli_type=''):

    if config != 'no':
        return False
    if get_ospf_cli_type(dut, cli_type=cli_type) == 'klish':
        return True

    return False


def get_ospf_router_cmd(vrf='default', instance=''):

    if vrf == 'default' or vrf == '':
        vrf_str = ''
    else:
        vrf_str = "vrf {}".format(vrf)
    if instance:
        ospf_cmd = "router ospf {} {}".format(instance, vrf_str)
    else:
        ospf_cmd = "router ospf {}".format(vrf_str)

    return ospf_cmd


def config_ospf_router(dut, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    action_str = 'Config' if config == 'yes' else 'Unconfig'
    st.log("OSPF - {}uring OSPF router {} {} {}".format(action_str, dut, vrf, instance))

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
    ### Forcing unconfig to klish due to JIRA:58935
    if cli_type in get_supported_ui_type_list() and config!='yes':
        cli_type = 'klish'

    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        if config == 'yes':
            ospf_obj.Enable = True
            result = ospf_obj.configure(dut, cli_type=cli_type)
        else:
            result = ospf_obj.unConfigure(dut, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config of Ospf Router: {}'.format(result.data))
            return False
        return True
    elif cli_type in ['vtysh', 'klish']:
        cmd = get_ospf_router_cmd(vrf, instance)
        cmd_str = " {} {}".format(cmd_pfx, cmd)
        command.append(cmd_str)
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_router'].format(vrf_str)
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_router_base'].format(vrf_str)
            data = {"openconfig-network-instance:network-instance": [
                    {"name": vrf_str,
                     "protocols": {
                         "protocol": [
                             {"identifier": "OSPF",
                              "name": "ospfv2",
                              "ospfv2": {"global": {"config": {"openconfig-ospfv2-ext:enable": True}}}
                              }]
                     }}]
                    }
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            url = rest_urls['config_ospfv2_global_config'].format(vrf_str)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_id(dut, router_id, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf

    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', Enable=True, NetworkInstance=ni_obj)
        if config == 'yes':
            ospf_obj.Ospfv2RouterId = router_id
            result = ospf_obj.configure(dut, cli_type=cli_type)
        else:
            result = ospf_obj.unConfigure(dut, target_attr=ospf_obj.Ospfv2RouterId, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config of Ospf Router-id: {}'.format(result.data))
            return False
        return True
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
            cmd_str = "{} ospf router-id".format(cmd_pfx)
        else:
            cmd_str = "{} ospf router-id {}".format(cmd_pfx, router_id)
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_router_id'].format(vrf_str)
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            data = {"ospfv2": {"global": {"config": {"openconfig-ospfv2-ext:enable": True, "openconfig-network-instance:router-id": router_id}}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_network(dut, networks, area, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    if not isinstance(networks, list):
        networks = [networks]

    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf

    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        if str(area) == '0':
            area = '0.0.0.0'
        ospf_area_obj = umf_ni.Area(Identifier=area, Protocol=ospf_proto_obj)
        operation = Operation.CREATE
        result = ospf_area_obj.configure(dut, operation=operation, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config of Ospf Area:\n {}'.format(result.data))
            return False
        for network in networks:
            network = str(network)
            ospf_nw_obj = umf_ni.NetworksNetwork(AddressPrefix=network, Area=ospf_area_obj)
            if config == 'yes':
                operation = Operation.CREATE
                result = ospf_nw_obj.configure(dut, operation=operation, cli_type=cli_type)
            else:
                result = ospf_nw_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of Ospf Network: {}'.format(result.data))
                return False
        return True
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        for network in networks:
            cmd_str = "{} network {} area {}".format(cmd_pfx, network, area)
            command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        #return validate_config_result(command, result, ["Please remove", "find specified"])
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if str(area) == '0':
            area = '0.0.0.0'
        for network in networks:
            if not cmd_pfx:
                url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
                data = {"ospfv2": {"openconfig-network-instance:areas": {"area": [{"openconfig-ospfv2-ext:networks": {"network": [{"config": {"openconfig-ospfv2-ext:address-prefix": network, "address-prefix": network}, "address-prefix": network}]}, "identifier": area}]}}}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                    return False
            else:
                url = rest_urls['config_ospfv2_network'].format(vrf_str, area, network.replace('/', '%2F'))
                if not delete_rest(dut, http_method='delete', rest_url=url):
                    return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_area_authentication(dut, area, msg_digest='', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} area {} authentication".format(cmd_pfx, area)
        else :
            cmd_str = "{} area {} authentication {}".format(cmd_pfx, area, msg_digest)
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_rfc_compatible'].format(vrf_str, area)
        if not cmd_pfx:
            data = {"openconfig-ospfv2-ext:authentication-type": "TEXT"}
            if msg_digest != '':
                data = {"openconfig-ospfv2-ext:authentication-type": "MD5HMAC"}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_area_default_cost(dut, area, cost, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} area {} default-cost".format(cmd_pfx, area)
        else :
            cmd_str = "{} area {} default-cost {}".format(cmd_pfx, area, cost)

        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")
        if not cmd_pfx:
            data = {"openconfig-ospfv2-ext:config": {"default-cost": cost}}
            url = rest_urls['config_ospfv2_area_stub'].format(vrf_str, area)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            url = rest_urls['config_ospfv2_area_stub_default_cost'].format(vrf_str, area)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True

    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_area_export_list(dut, area, list_name, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type == 'vtysh':
        cmd_str = get_ospf_router_cmd(vrf, instance)

        command.append(cmd_str)

        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} area {} export-list".format(cmd_pfx, area)
        else :
            cmd_str = "{} area {} export-list {}".format(cmd_pfx, area, list_name)
        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put", "klish"]:
        st.error("cli is unsupported for this UI-Type: {}".format(cli_type))
        return False
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False



def config_ospf_router_area_import_list(dut, area, list_name, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type == 'vtysh':
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} area {} import-list".format(cmd_pfx, area)
        else :
            cmd_str = "{} area {} import-list {}".format(cmd_pfx, area, list_name)
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put", "klish"]:
        st.error("cli is unsupported for this UI-Type: {}".format(cli_type))
        return False
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_area_filter_list(dut, area, list_name, direction, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #direction = <in|out>
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} area {} filter-list prefix {}".format(cmd_pfx, area, direction)
        else :
            cmd_str = "{} area {} filter-list prefix {} {}".format(cmd_pfx, area, list_name, direction)
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_area_filter_list'].format(vrf_str, area, direction)
        if not cmd_pfx:
            data = {"openconfig-ospfv2-ext:filter-list-{}".format(direction): {"config": {"name": list_name}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_area_nssa(dut, area, nssa_option='', vrf='default', instance='', config='yes', cli_type=''):
    #API_Not_Used: To Be removed in CyrusPlus
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type == 'vtysh':
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #nssa_option = <translate-candidate|translate-never|translate-always> | no-summary | ''

        cmd_str = "{} area {} nssa {}".format(cmd_pfx, area, nssa_option)
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put", "klish"]:
        st.error("cli is unsupported for this UI-Type: {}".format(cli_type))
        return False
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_area_range_cost(dut, area, range_prefix, cost='', advertise='', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
    if str(area) == '0':
        area = '0.0.0.0'
    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)

        if config == 'yes':
            inter_area_obj = umf_ni.InterAreaPolicy(SrcArea=area)
            ospf_range_obj = umf_ni.Range(AddressPrefix=range_prefix)

            if advertise != '':
                ospf_range_obj.Advertise = True
            if cost != '':
                ospf_range_obj.Metric = integer_parse(cost)
            #result = ospf_range_obj.configure(dut, cli_type=cli_type)
            inter_area_obj.add_Range(ospf_range_obj)
            ospf_proto_obj.add_InterAreaPolicy(inter_area_obj)

            result = ospf_proto_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of Ospf Area Range: {}'.format(result.data))
                return False
        else:
            inter_area_obj = umf_ni.InterAreaPolicy(SrcArea=area, Protocol=ospf_proto_obj)
            ospf_range_obj = umf_ni.Range(AddressPrefix=range_prefix, InterAreaPolicy=inter_area_obj)

            result_flag = True
            if cost != '':
                result = ospf_range_obj.unConfigure(dut, target_attr=ospf_range_obj.Metric, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            elif advertise != '':
                result = ospf_range_obj.unConfigure(dut, target_attr=ospf_range_obj.Advertise, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            else:
                result = ospf_range_obj.unConfigure(dut, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            if not result_flag:
                st.log('test_step_failed: UnConfig of Ospf Area Range Parameters: {}'.format(result.data))
                return False

            '''inter_area_obj = umf_ni.InterAreaPolicy(SrcArea=area)
            ospf_range_obj = umf_ni.Range(AddressPrefix=range_prefix, InterAreaPolicy=inter_area_obj)

            if advertise != '':
                target_attr = ospf_range_obj.Advertise
            elif cost != '':
                target_attr = ospf_range_obj.Metric
            else:
                target_attr = ospf_range_obj.AddressPrefix

            #inter_area_obj.add_Range(ospf_range_obj)
            ospf_proto_obj.add_InterAreaPolicy(inter_area_obj)
            cli_type = 'rest'
            result = ospf_range_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: UnConfig of Ospf Area Range Parameters: {}'.format(result.data))
                return False'''
        return True
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        cmd_str = "{} area {} range {}".format(cmd_pfx, area, range_prefix)
        if advertise != '':
            cmd_str += " advertise"
        if cost != '':
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str += " cost"
            else :
                cmd_str += " cost {}".format(cost)
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            data = {"ospfv2": {"global": {"inter-area-propagation-policies": {"openconfig-ospfv2-ext:inter-area-policy": [{"src-area": area, "ranges": {"range": [{"config": {"openconfig-ospfv2-ext:address-prefix": range_prefix}, "address-prefix": range_prefix}]}}]}}}}
            if advertise != '':
                data['ospfv2']['global']['inter-area-propagation-policies']['openconfig-ospfv2-ext:inter-area-policy'][0]['ranges']['range'][0]['config'].update({"openconfig-ospfv2-ext:advertise": True})
            elif cost != '':
                data['ospfv2']['global']['inter-area-propagation-policies']['openconfig-ospfv2-ext:inter-area-policy'][0]['ranges']['range'][0]['config'].update({"openconfig-ospfv2-ext:metric": integer_parse(cost)})
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if advertise != '':
                url = rest_urls['config_ospfv2_area_range_cost_advertise'].format(vrf_str, area, range_prefix.replace('/', '%2F'))
            elif cost != '':
                url = rest_urls['config_ospfv2_area_range_cost_metric'].format(vrf_str, area, range_prefix.replace('/', '%2F'))
            else:
                url = rest_urls['config_ospfv2_area_range_cost'].format(vrf_str, area, range_prefix.replace('/', '%2F'))
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_area_range_not_advertise(dut, area, range_prefix, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        cmd_str = "{} area {} range {} not-advertise".format(cmd_pfx, area, range_prefix)
        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_area_range_cost_advertise'].format(vrf_str, area, range_prefix.replace('/', '%2F'))
        if not cmd_pfx:
            data = {"openconfig-ospfv2-ext:advertise": False}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

def config_ospf_router_area_range_substitute_prefix(dut, area, range_prefix, subs_prefix, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vtysh', 'klish']:

        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} area {} range {} substitute".format(cmd_pfx, area, range_prefix)
        else :
            cmd_str = "{} area {} range {} substitute {}".format(cmd_pfx, area, range_prefix, subs_prefix)
        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_area_range_cost_enable'].format(vrf_str, area, range_prefix.replace('/', '%2F'))
            data = {"openconfig-ospfv2-ext:config": {"substitue-prefix": subs_prefix}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            url = rest_urls['config_ospfv2_area_range_cost_substitute_prefix'].format(vrf_str, area, range_prefix.replace('/', '%2F'))
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

def config_ospf_router_area_shortcut(dut, area, shortcut='default', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #shortcut= <default|enable|disable>
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} area {} shortcut".format(cmd_pfx, area)
        else :
            cmd_str = "{} area {} shortcut {}".format(cmd_pfx, area, shortcut)
        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")
        shortcut = shortcut.upper()
        url = rest_urls['config_ospfv2_area_shortcut'].format(vrf_str, area)
        if not cmd_pfx:
            data = { "openconfig-ospfv2-ext:shortcut": shortcut}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

def config_ospf_router_area_stub(dut, area, no_summary='', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf

    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        if str(area) == '0':
            area = '0.0.0.0'
        ospf_area_obj = umf_ni.Area(Identifier=area, Protocol=ospf_proto_obj)
        if config =='yes':
            ospf_area_obj.Enable = True
            if no_summary != '':
                ospf_area_obj.NoSummary = True
            result = ospf_area_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of Ospf Stub area: {}'.format(result.data))
                return False
        else:
            if no_summary != '':
                result = ospf_area_obj.unConfigure(dut, target_attr=ospf_area_obj.NoSummary, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: UnConfig of Ospf area NoSummary: {}'.format(result.data))
                    return False
            else:
                result = ospf_area_obj.unConfigure(dut, target_attr=ospf_area_obj.Enable, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: UnConfig of Ospf Stub area: {}'.format(result.data))
                    return False
        return True
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        cmd_str = "{} area {} stub".format(cmd_pfx, area)
        if no_summary != '':
            cmd_str += " no-summary"
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            if no_summary != '':
                data = {"ospfv2": {"openconfig-network-instance:areas": {"area": [{"identifier": area, "openconfig-ospfv2-ext:stub": {"config": {"no-summary": True, "openconfig-ospfv2-ext:enable": True}}}]}}}
            else:
                data = {"ospfv2": {"openconfig-network-instance:areas": {"area": [{"identifier": area, "openconfig-ospfv2-ext:stub": {"config": {"openconfig-ospfv2-ext:enable": True}}}]}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if no_summary != '':
                url = rest_urls['config_ospfv2_area_stub_nosummary'].format(vrf_str, area)
            else:
                url = rest_urls['config_ospfv2_area_stub_enable'].format(vrf_str, area)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_autocost_refbw(dut, bandwidth, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf

    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        if config == 'yes':
            ospf_proto_obj.AutoCostReferenceBandwidth = integer_parse(bandwidth)
            result = ospf_proto_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of Ospf auto-cost reference bandwidth: {}'.format(result.data))
                return False
        else:
            target_attr = ospf_proto_obj.AutoCostReferenceBandwidth
            result = ospf_proto_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: UnConfig of Ospf auto-cost reference bandwidth: {}'.format(result.data))
                return False
        return True
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #bandwidth 1-4294967 Mbps
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} auto-cost reference-bandwidth".format(cmd_pfx)
        else :
            cmd_str = "{} auto-cost reference-bandwidth {}".format(cmd_pfx, bandwidth)
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=get_ospf_cli_type(dut, cli_type=cli_type))
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_auto_cost_refbw'].format(vrf_str)
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            data = {"ospfv2": {"global": {"config": {"openconfig-ospfv2-ext:enable": True, "openconfig-ospfv2-ext:auto-cost-reference-bandwidth": integer_parse(bandwidth)}}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

def config_ospf_opaque_capability(dut, vrf='default', config='yes', cli_type=''):
    """
    This proc is used for configuring OSPF Opaque LSA Capability
    :Author:Ramachandran Sathianandan:
    :param :dut:
    :param :vrf:
    :param :config:
    :return:
    """
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    if cli_type  in get_supported_ui_type_list() or cli_type in ["klish"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', Enable=True, NetworkInstance=ni_obj)
        if config == 'yes':
            setattr(ospf_obj, 'OpaqueLsaCapability',True)
            result = ospf_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('{} test_step_failed: Config of Ospf opaque capability: {}'.format(cli_type,result.data))
                return False
        else:
            target_attr = getattr(ospf_obj, 'OpaqueLsaCapability')
            result = ospf_obj.unConfigure(dut, target_attr=target_attr, target_attr_name="OpaqueLsaCapability", cli_type=cli_type)
            if not result.ok():
                st.log('{} test_step_failed: Unconfig of Ospf opaque capability {}'.format(cli_type,result.data))
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

def config_ospf_gr(dut, **kwargs):
    """
    This proc is used for configuring OSPFv2 Graceful-Restart commands
    :Author:Ramachandran Sathianandan:
    :param :dut:
    :param :vrf:
    :param :config:
    :param :gr:
    :param :grace_period:
    :param :helper:
    :param :strict_lsa:
    :param :planned_only:
    :param :helper_grace_time:
    :param :helper_nbrs:
    :return:
    """
    vrf = kwargs.get('vrf')
    config = kwargs.get('config')
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
    config = 'yes' if config == 'yes' or config == ''  else config
    if kwargs.get('helper_nbrs') and not isinstance(kwargs.get('helper_nbrs'), list): kwargs['helper_nbrs'] = [kwargs['helper_nbrs']]
    cli_type = get_ospf_cli_type(dut, **kwargs)
    if cli_type  in get_supported_ui_type_list() or cli_type in ["klish"]:
        gr_attr_list = {
            'gr': ['Ospfv2GREnabled', kwargs.get('gr', None)],
            'grace_period': ['GracePeriod', kwargs.get('grace_period', None)],
            'helper': ['HelperOnly', kwargs.get('helper', None)],
            'strict_lsa': ['StrictLsaChecking', kwargs.get('strict_lsa', None)],
            'planned_only': ['PlannedOnly', kwargs.get('planned_only', None)],
            'helper_grace_time': ['SupportedGraceTime', kwargs.get('helper_grace_time', None)],
            'helper_nbrs':['NeighbourId', kwargs.get('helper_nbrs', None)],
            'helper_exit_reason': ['GrLastExitReason', kwargs.get('helper_exit_reason', None)],
            'active_restart_nbrs': ['GrHelperActiveRestarterCount', kwargs.get('active_restart_nbrs', None)]
        }
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        if config in ['yes', 'verify']:
            for key, attr_value in  gr_attr_list.items():
                if key in kwargs and attr_value[1] is not None:
                    if key == 'helper_nbrs' :
                        nbrs = attr_value[1]
                        for nbr in attr_value[1]:
                            #nbr = str(nbr)
                            #ospf_gr_helpers_obj = umf_ni.Helper(NeighbourId=nbr, Protocol=ospf_proto_obj)
                            ospf_gr_helpers_obj = umf_ni.Helper(NeighbourId=nbr)
                            ospf_proto_obj.add_Helper(ospf_gr_helpers_obj)
                            #operation = Operation.CREATE
                            #result = ospf_gr_helpers_obj.configure(dut, operation=operation, cli_type=cli_type)
                            #if not result.ok():
                            #    st.log('{} test_step_failed: GR config - helper neighbor: {}'.format(cli_type,result.data))
                            #    return False
                    else:
                        setattr(ospf_proto_obj, attr_value[0], attr_value[1])
            if config in ['verify']:
                return ospf_proto_obj
            #result = ospf_proto_obj.configure(dut, cli_type=cli_type)
            operation = Operation.CREATE
            result = ospf_proto_obj.configure(dut, operation=operation, cli_type=cli_type)
            if not result.ok():
                st.log('{} test_step_failed: GR Config - Options {}'.format(cli_type,result.data))
                return False
            return True
        else:
            for key, attr_value in  gr_attr_list.items():
                if key in kwargs and attr_value[1] is not None:
                    if key == 'strict_lsa':
                        if attr_value[1] == 'False':
                            setattr(ospf_proto_obj, attr_value[0], True)
                        elif attr_value[1] == 'True':
                            setattr(ospf_proto_obj, attr_value[0], False)
                        operation = Operation.CREATE
                        result = ospf_proto_obj.configure(dut, operation=operation, cli_type=cli_type)
                        #result = ospf_proto_obj.configure(dut, cli_type=cli_type)
                        if not result.ok():
                            st.log('{} test_step_failed: Config gr-helper strict lsa {}'.format(cli_type,result.data))
                            return False
                    elif key == 'helper_nbrs' :
                        nbrs = attr_value[1]
                        for nbr in nbrs:
                            nbr = str(nbr)
                            ospf_gr_helpers_obj = umf_ni.Helper(NeighbourId=nbr, Protocol=ospf_proto_obj)
                            result = ospf_gr_helpers_obj.unConfigure(dut, cli_type=cli_type)
                            if not result.ok():
                                st.log('{} test_step_failed: Unonfig Ospf gr helper neighbor: {}'.format(cli_type,result.data))
                                return False
                    else:
                        target_attr = getattr(ospf_proto_obj, attr_value[0])
                        result = ospf_proto_obj.unConfigure(dut, target_attr=target_attr, target_attr_name=attr_value[0], cli_type=cli_type)
                        if not result.ok():
                            st.log('{} test_step_failed: Unconfig gr {}'.format(cli_type,result.data))
                            return False
            return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

def verify_ospf_gr(dut, **kwargs):
    cli_type = get_ospf_cli_type(dut, **kwargs)
    kwargs['config'] = 'verify'
    if cli_type  in get_supported_ui_type_list() or cli_type in ["klish"]:
        ospf_proto_obj = config_ospf_gr(dut, **kwargs)
        filter_type = kwargs.get('filter_type', 'ALL')
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        result = ospf_proto_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Match Not Found for OSPF GR:')
            return False
    return True


def config_ospf_router_compatibility_rfc(dut, rfc='rfc1583', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        if config == 'yes':
            ospf_proto_obj.OspfRfc1583Compatible = True
            result = ospf_proto_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of Ospf RFC1583 compatibility: {}'.format(result.data))
                return False
        else:
            target_attr = ospf_proto_obj.OspfRfc1583Compatible
            result = ospf_proto_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: UnConfig of Ospf RFC1583 compatibility: {}'.format(result.data))
                return False
        return True
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)
        cmd_str = "{} compatible {}".format(cmd_pfx, rfc)
        command.append(cmd_str)
        command.append('exit')
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_rfc_compatible'].format(vrf_str)
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            data = {"ospfv2": {"global": {"config": {"openconfig-ospfv2-ext:ospf-rfc1583-compatible": True, "openconfig-ospfv2-ext:enable": True}}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

    if cli_type in ['vtysh', 'klish']:
        result = st.config(dut, command, type=get_ospf_cli_type(dut, cli_type=cli_type))
        return validate_config_result(command, result, "")


def config_ospf_router_compatibility_flag(dut, flag='rfc1583', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type == 'vtysh':
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        cmd_str = "{} ospf {}compatibility".format(cmd_pfx, flag)
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put", "klish"]:
        st.error("cli is unsupported for this UI-Type: {}".format(cli_type))
        return False
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_abr_type(dut, abrtype='standard', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #abrtype cisco|ibm|shortcut|standard
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} ospf abr-type".format(cmd_pfx)
        else :
            cmd_str = "{} ospf abr-type {}".format(cmd_pfx, abrtype)

        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=get_ospf_cli_type(dut, cli_type=cli_type))
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_rfc_compatible'].format(vrf_str)
        if not cmd_pfx:
            data = {"openconfig-ospfv2-ext:ospf-rfc1583-compatible": True}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True


def config_ospf_router_write_multiplier(dut, multiplier, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        # 1- 100
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} write-multiplier".format(cmd_pfx)
        else :
            cmd_str = "{} write-multiplier {}".format(cmd_pfx, multiplier)

        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=get_ospf_cli_type(dut, cli_type=cli_type))
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_router_global_config'].format(vrf_str)
        if not cmd_pfx:
            data = {"openconfig-network-instance:config": {"openconfig-ospfv2-ext:write-multiplier": multiplier}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

def config_ospf_router_default_metric(dut, metric, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} default-metric".format(cmd_pfx)
        else :
            cmd_str = "{} default-metric {}".format(cmd_pfx, metric)

        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_router_global_config'].format(vrf_str)
        if not cmd_pfx:
            data = {"openconfig-network-instance:config": {"openconfig-ospfv2-ext:default-metric": metric}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False



def config_ospf_router_distance(dut, dist_type, distance, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        if config == 'yes':
            if dist_type == '':
                ospf_proto_obj.All = distance
            if dist_type == 'intra-area':
                ospf_proto_obj.IntraArea = distance
            if dist_type == 'external':
                ospf_proto_obj.External = distance
            if dist_type == 'inter-area':
                ospf_proto_obj.InterArea = distance

            result = ospf_proto_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of Ospf Router Distance: {}'.format(result.data))
                return False
        else:
            if dist_type == '':
                target_attr = ospf_proto_obj.All
            if dist_type == 'intra-area':
                target_attr = ospf_proto_obj.IntraArea
            if dist_type == 'external':
                target_attr = ospf_proto_obj.External
            if dist_type == 'inter-area':
                target_attr = ospf_proto_obj.InterArea

            result = ospf_proto_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: UnConfig of Ospf Router Distance: {}'.format(result.data))
                return False
        return True
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #dist_type=intra-area|inter-area |external
        if dist_type == '':
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str = "{} distance".format(cmd_pfx)
            else :
                cmd_str = "{} distance {}".format(cmd_pfx, distance)
        else:
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str = "{} distance ospf {}".format(cmd_pfx, dist_type)
            else :
                cmd_str = "{} distance ospf {} {}".format(cmd_pfx, dist_type , distance)

        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_distance'].format(vrf_str)
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            if dist_type == '':
                data = {"ospfv2": {"global": {"openconfig-ospfv2-ext:distance": {"config": {"openconfig-ospfv2-ext:all": distance}}}}}
            if dist_type == 'intra-area':
                data = {"ospfv2": {"global": {"openconfig-ospfv2-ext:distance": {"config": {"openconfig-ospfv2-ext:intra-area": distance}}}}}
            if dist_type == 'external':
                data = {"ospfv2": {"global": {"openconfig-ospfv2-ext:distance": {"config": {"openconfig-ospfv2-ext:external": distance}}}}}
            if dist_type == 'inter-area':
                data = {"ospfv2": {"global": {"openconfig-ospfv2-ext:distance": {"config": {"openconfig-ospfv2-ext:inter-area": distance}}}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_distribute_list(dut, list_name, dist_type, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type == 'vtysh':
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #dist_type=kernel|connected|static|rip|isis|bgp|eigrp|nhrp|table|vnc|babel|sharp|openfabric
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} distribute-list out {}".format(cmd_pfx, dist_type)
        else :
            cmd_str = "{} distribute-list {} out {}".format(cmd_pfx, list_name, dist_type)
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put", "klish"]+get_supported_ui_type_list():
        st.error("cli is unsupported for this UI-Type: {}".format(cli_type))
        return False
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_redistribute(dut, redist_type, metric='', metric_type='', routemap='',
                                    tableid='', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf

    if cli_type in get_supported_ui_type_list():
        redist_type = redist_type.upper()
        if redist_type == 'CONNECTED': redist_type = 'DIRECTLY_CONNECTED'
        if metric_type: metric_type = "TYPE_" + str(metric_type)
        if metric: metric = integer_parse(metric)

        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        dist_obj = umf_ni.DistributeList(
            CommonOpenconfignetworkinstancenetworkinstancesnetworkinstanceprotocolsprotocolospfv2globalopenconfigospfv2extroutedistributionpoliciesdistributelistconfigprotocol=redist_type,
            Direction='IMPORT', Protocol=ospf_proto_obj)

        if config == 'yes':
            operation = Operation.CREATE
            if metric != '':
                dist_obj.Metric = metric
            if metric_type != '':
                dist_obj.MetricType = metric_type
            if routemap != '':
                dist_obj.RouteMap = routemap
           # result = dist_obj.configure(dut, cli_type=cli_type)
            result = dist_obj.configure(dut, operation=operation, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of Ospf Redistribution: {}'.format(result.data))
                return False
        else:
            result_flag = True
            if metric_type != '':
                result = dist_obj.unConfigure(dut, target_attr=dist_obj.MetricType, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            elif metric != '':
                result = dist_obj.unConfigure(dut, target_attr=dist_obj.Metric, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            elif routemap != '':
                result = dist_obj.unConfigure(dut, target_attr=dist_obj.RouteMap, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            else:
                result = dist_obj.unConfigure(dut, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            if not result_flag:
                st.log('test_step_failed: UnConfig of Ospf Redistribution Parameters: {}'.format(result.data))
                return False
        return True

    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        # redistribute <kernel|connected|static|bgp> [{metric (0-16777214)|metric-type (1-2)| route-map WORD}]
        # redistribute <ospf|table> (1-65535) [{metric (0-16777214)|metric-type (1-2)|route-map WORD}]
        cmd_str = "{} redistribute {}".format(cmd_pfx, redist_type)

        if redist_type in [ 'ospf', 'table' ]:
            cmd_str +=  " {}".format(tableid)

        if metric !='':
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str +=  " metric"
            else :
                cmd_str +=  " metric {}".format(metric)

        if metric_type !='':
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str +=  " metric-type"
            else :
                cmd_str +=  " metric-type {}".format(metric_type)

        if routemap !='':
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str +=  " route-map"
            else :
                cmd_str +=  " route-map {}".format(routemap)

        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")

    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        redist_type = redist_type.upper()
        if redist_type == 'CONNECTED': redist_type = 'DIRECTLY_CONNECTED'
        if metric_type: metric_type = "TYPE_" + str(metric_type)
        if metric: metric = integer_parse(metric)
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            data = {'ospfv2': {'global': {'openconfig-ospfv2-ext:route-distribution-policies': {'distribute-list': [{'protocol': redist_type, 'direction': 'IMPORT', 'config': {'direction': 'IMPORT', 'protocol': redist_type}}]}}}}
            if metric != '':
                dict1 = {"openconfig-ospfv2-ext:metric": metric}
                data['ospfv2']['global']['openconfig-ospfv2-ext:route-distribution-policies']['distribute-list'][0]['config'].update(dict1)

            if metric_type != '':
                dict1 = {"openconfig-ospfv2-ext:metric-type": metric_type}
                data['ospfv2']['global']['openconfig-ospfv2-ext:route-distribution-policies']['distribute-list'][0]['config'].update(dict1)
            if routemap != '':
                dict1 = {"openconfig-ospfv2-ext:route-map": routemap}
                data['ospfv2']['global']['openconfig-ospfv2-ext:route-distribution-policies']['distribute-list'][0]['config'].update(dict1)

            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if metric_type != '':
                url = rest_urls['config_ospfv2_route_redistribute_metric_type'].format(vrf_str, redist_type)
            elif metric != '':
                url = rest_urls['config_ospfv2_route_redistribute_metric'].format(vrf_str,redist_type)
            elif routemap != '':
                url = rest_urls['config_ospfv2_route_redistribute_route_map'].format(vrf_str, redist_type)
            else:
                url = rest_urls['config_ospfv2_route_redistribute'].format(vrf_str, redist_type)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_default_information(dut, dinfo_type, dinfo_value, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf

    if cli_type in get_supported_ui_type_list():
        route_type = "DEFAULT_ROUTE"
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        dist_obj = umf_ni.DistributeList(
            CommonOpenconfignetworkinstancenetworkinstancesnetworkinstanceprotocolsprotocolospfv2globalopenconfigospfv2extroutedistributionpoliciesdistributelistconfigprotocol=route_type,
            Direction='IMPORT', Protocol=ospf_proto_obj)
        if config == 'yes':
            operation = Operation.CREATE
            if dinfo_type == 'metric':
                dinfo_value = integer_parse(dinfo_value)
                dist_obj.Always = True
                dist_obj.Metric = dinfo_value
            elif dinfo_type == 'metric-type':
                dinfo_value = "TYPE_" + str(dinfo_value)
                dist_obj.Always = True
                dist_obj.MetricType = dinfo_value
            elif dinfo_type == 'route-map':
                dist_obj.Always = True
                dist_obj.RouteMap = dinfo_value
            elif dinfo_type == 'always':
                dist_obj.Always = True
            else:
                st.log("Invalid parameter {} {}".format(dinfo_type, dinfo_value))
                return False
            result = dist_obj.configure(dut, operation=operation, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of Ospf Default Information Originate: {}'.format(result.data))
                return False
        else:
            result_flag = True
            if dinfo_type == 'metric-type':
                result = dist_obj.unConfigure(dut, target_attr=dist_obj.MetricType, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            elif dinfo_type == 'metric':
                result = dist_obj.unConfigure(dut, target_attr=dist_obj.Metric, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            elif dinfo_type == 'route-map':
                result = dist_obj.unConfigure(dut, target_attr=dist_obj.RouteMap, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            elif dinfo_type == 'always':
                result = dist_obj.unConfigure(dut, target_attr=dist_obj.Always, cli_type=cli_type)
                result_flag = result_flag and result.ok()
            if not result_flag:
                st.log('test_step_failed: UnConfig of Ospf Default Information originate Parameters: {}'.format(result.data))
                return False
        return True
    elif cli_type in ['vytsh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        # [{always|metric (0-16777214)|metric-type (1-2)|route-map WORD}]

        cmd_str = "{} default-information originate".format(cmd_pfx)
        if dinfo_type == 'always':
            cmd_str += " always"
        elif dinfo_type in [ 'metric', 'metric-type', 'route-map']:
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str += " always {}".format(dinfo_type)
            else :
                cmd_str += " always {} {}".format(dinfo_type, dinfo_value)
        else:
            st.log("Invalid parameter {} {}".format(dinfo_type, dinfo_value))
            return False
        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=get_ospf_cli_type(dut, cli_type=cli_type))
        return validate_config_result(command, result, "")

    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        route_type = "DEFAULT_ROUTE"
        url = rest_urls['config_ospfv2_route_redistribute'].format(vrf_str, route_type)

        if not cmd_pfx:
            if dinfo_type == 'metric':
                dinfo_value = integer_parse(dinfo_value)
                data = {"openconfig-ospfv2-ext:config": {"protocol": route_type, "always": True, "metric": dinfo_value}}
            elif dinfo_type == 'metric-type':
                metric_type = "TYPE_" + str(dinfo_value)
                data = {"openconfig-ospfv2-ext:config": {"protocol": route_type, "always": True,
                                                         "metric-type": metric_type}}
            elif dinfo_type == 'route-map':
                data = {"openconfig-ospfv2-ext:config": {"protocol": route_type, "always": True, "route-map": dinfo_value}}
            else:
                st.log("Invalid parameter {} {}".format(dinfo_type, dinfo_value))
                return False
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if dinfo_type == 'metric':
                url = rest_urls['config_ospfv2_route_redistribute_metric'].format(vrf_str, route_type)
            elif dinfo_type == 'metric-type':
                url = rest_urls['config_ospfv2_route_redistribute_metric_type'].format(vrf_str, route_type)
            else:
                url = rest_urls['config_ospfv2_route_redistribute_route_map'].format(vrf_str, route_type)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
            url = rest_urls['config_ospfv2_route_default_info_originate_always'].format(vrf_str, route_type)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

def config_ospf_router_log_adjacency(dut, mode='', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in get_supported_ui_type_list():
        mode = 'BRIEF' if mode == '' or mode == 'brief' else 'DETAIL'
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        ospf_proto_obj.LogAdjacencyStateChanges = mode
        if not cmd_pfx:
            result = ospf_proto_obj.configure(dut, cli_type=cli_type)
        else:
            result = ospf_proto_obj.unConfigure(dut, target_attr=ospf_proto_obj.LogAdjacencyStateChanges, cli_type=cli_type)
        if not result.ok():
            st.log('test_step_failed: Config of Ospf log adjacency: {}'.format(result.data))
            return False
        return True

    if cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #mode  '' detail
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} log-adjacency-changes".format(cmd_pfx)
        else :
            cmd_str = "{} log-adjacency-changes {}".format(cmd_pfx, mode)
        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=get_ospf_cli_type(dut, cli_type=cli_type))
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_log_adj_changes'].format(vrf_str)
        if not cmd_pfx:
            mode = 'BRIEF' if mode == '' or mode == 'brief' else 'DETAIL'
            data = {"openconfig-ospfv2-ext:log-adjacency-state-changes": mode}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

def config_ospf_router_max_metric(dut, mmetric_type, mmetric_value, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf

    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        if config == 'yes':
            if mmetric_type == 'administrative':
                ospf_proto_obj.MaxMetricAdministrative = True
            elif mmetric_type == 'on-startup':
                ospf_proto_obj.OnStartup = integer_parse(mmetric_value)
            elif mmetric_type == 'on-shutdown':
                st.error("mmetric_type:on_shutdown is not supported in Klish/Rest/Gnmi")
                return False
            else:
                st.log("Invalid parameter {} {}".format(mmetric_type, mmetric_value))
                return False
            result = ospf_proto_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of Ospf max-metric router lsa: {}'.format(result.data))
                return False
        else:
            if mmetric_type == 'administrative':
                target_attr = ospf_proto_obj.MaxMetricAdministrative
            elif mmetric_type == 'on-startup':
                target_attr = ospf_proto_obj.OnStartup
            elif mmetric_type == 'on-shutdown':
                st.error("mmetric_type:on_shutdown is not supported in Klish/Rest/Gnmi")
                return False
            else:
                st.log("Invalid parameter {} {}".format(mmetric_type, mmetric_value))
                return False
            result = ospf_proto_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: UnConfig of Ospf max-metric router lsa: {}'.format(result.data))
                return False
        return True
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #value on-shutdown 5-100 seconds on-startup 5-86400
        cmd_str = "{} max-metric router-lsa".format(cmd_pfx)
        if mmetric_type == 'administrative':
            cmd_str += " administrative"
        elif mmetric_type in [ 'on-shutdown', 'on-startup']:
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str += " {}".format(mmetric_type)
            else :
                cmd_str += " {} {}".format(mmetric_type, mmetric_value)
        else:
            st.log("Invalid parameter {} {}".format(mmetric_type, mmetric_value))
            return False

        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        url = rest_urls['config_ospfv2_max_metric'].format(vrf_str)
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            if mmetric_type == 'administrative':
                data = {"ospfv2": {"global": {"timers": {"max-metric": {"config": {"openconfig-ospfv2-ext:administrative": True}}}}}}
            elif mmetric_type == 'on-startup':
                data = {"ospfv2": {"global": {"timers": {"max-metric": {"config": {"openconfig-ospfv2-ext:on-startup": integer_parse(mmetric_value)}}}}}}
            elif mmetric_type == 'on-shutdown':
                data = {"openconfig-network-instance:config": {"openconfig-ospfv2-ext:on-shutdown": integer_parse(mmetric_value)}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_neighbor_priority(dut, nbr_ip, priority='', poll_interval='', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type =='vytsh':
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #priority (0-255) [poll-interval (1-65525)]
        if priority == '' and poll_interval == '':
           st.log("Either priority or poll interval be present")
           return False

        cmd_str = "{}  neighbor {}".format(cmd_pfx, nbr_ip)

        if priority != '':
            cmd_str += " priority {}".format(priority)

        if poll_interval != '':
            cmd_str += " poll-interval {}".format(poll_interval)
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put", "klish"]:
        st.error("cli is unsupported for this UI-Type: {}".format(cli_type))
        return False
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_refresh_timer(dut, timer_value, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vytsh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #timer_value 10-1800 sec
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} refresh timer".format(cmd_pfx)
        else :
            cmd_str = "{} refresh timer {}".format(cmd_pfx, timer_value)

        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls", "routing")

        if not cmd_pfx:
            url = rest_urls['config_ospfv2_router_global_timers_config'].format(vrf_str)
            data = {"openconfig-network-instance:config": {"openconfig-ospfv2-ext:refresh-timer": timer_value}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            url = rest_urls['config_ospfv2_router_global_timers_refresh_timer'].format(vrf_str)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))


def config_ospf_router_router_info(dut, scope='area', vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    if cli_type == 'vtysh':
        command = []
        # cmd_pfx = '' if config == 'yes' else 'no'

        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #scope area | as
        #cmd_str = "{} router-info {}".format(cmd_pfx, scope)
        if config == 'yes':
            cmd_str = "router-info {}".format(scope)
        else:
            cmd_str = "no router-info"
        command.append(cmd_str)
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put", "klish"]:
        st.error("cli is unsupported for this UI-Type: {}".format(cli_type))
        return False
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


def config_ospf_router_lsa_min_arrival_timer(dut, time_val, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vytsh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #time_val 0-600000 msec
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} timers lsa min-arrival".format(cmd_pfx)
        else :
            cmd_str = "{} timers lsa min-arrival {}".format(cmd_pfx, time_val)
        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls", "routing")
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_router_global_timers_config'].format(vrf_str)
            data = {"openconfig-network-instance:config": {"openconfig-ospfv2-ext:minimum-arrival": time_val}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            url = rest_urls['config_ospfv2_router_global_timers_minimum_arrival'].format(vrf_str)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))

def config_ospf_router_lsa_throttle_timer(dut, time_val, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vytsh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #time_val 0-5000 msec
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} timers throttle lsa all".format(cmd_pfx)
        else :
            cmd_str = "{} timers throttle lsa all {}".format(cmd_pfx, time_val)
        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls", "routing")
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_router_global_timers_config'].format(vrf_str)
            data = {"openconfig-network-instance:config": {"openconfig-ospfv2-ext:minimum-interval": time_val}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            url = rest_urls['config_ospfv2_router_global_timers_minimum_interval'].format(vrf_str)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))


def config_ospf_router_spf_throttle_timer(dut, delay, initial, maximum, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    if cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        # all 0-600000 msec
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
            cmd_str = "{} timers throttle spf".format(cmd_pfx)
        else :
            cmd_str = "{} timers throttle spf {} {} {}".format(cmd_pfx, delay, initial, maximum)
        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=get_ospf_cli_type(dut, cli_type=cli_type))
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls", "routing")
        url = rest_urls['config_ospfv2_router_global_timers_spf'].format(vrf_str)
        if not cmd_pfx:
            data = {"openconfig-network-instance:spf": {"config": {"initial-delay": initial, "maximum-delay": maximum, "openconfig-ospfv2-ext:throttle-delay": delay}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))


def config_ospf_router_passive_interface(dut, interfaces, if_ip='', non_passive='', vrf='default', instance='', config='yes', cli_type='', **kwargs):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    skip_error = kwargs.pop('skip_error_check', False)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    link_ip = if_ip
    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf
    if cli_type in get_supported_ui_type_list():
        ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
        ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)

        psvif_type = True if non_passive != '' else False

        for index, interface in enumerate(interfaces):
            ip = link_ip[index] if len(link_ip) >= (index + 1) and link_ip[index] != '' else '0.0.0.0'
            if config == 'yes':
                if interface == 'default' or interface == '':
                    ospf_proto_obj.PassiveInterfaceDefault = True
                    result = ospf_proto_obj.configure(dut, cli_type=cli_type)
                else:
                    operation = Operation.CREATE
                    index = int(get_subinterface_index(dut, interface))
                    intf_name = get_phy_port(interface)
                    passive_intf_obj = umf_ni.PassiveInterface(Name=intf_name, Subinterface=index,
                                                        Address=ip, NonPassive=psvif_type, Protocol=ospf_proto_obj)
                    result = passive_intf_obj.configure(dut, cli_type=cli_type, operation=operation,)
                if not result.ok():
                    st.log('test_step_failed: Config of Ospf passive interface:\n {}'.format(result.data))
                    return False
            else:
                if interface == 'default' or interface == '':
                    target_attr = ospf_proto_obj.PassiveInterfaceDefault
                    result = ospf_proto_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                else:
                    index = int(get_subinterface_index(dut, interface))
                    intf_name = get_phy_port(interface)
                    passive_intf_obj = umf_ni.PassiveInterface(Name=intf_name, Subinterface=index,
                                                               Address=ip, NonPassive=psvif_type,
                                                               Protocol=ospf_proto_obj)
                    result = passive_intf_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: UnConfig of Ospf passive interface:\n {}'.format(result.data))
                    return False
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        for index, interface in enumerate(interfaces):
            cmd_pfx = '' if config == 'yes' else 'no'

            if interface == 'default' or interface == '' :
                cmd_str = "{} passive-interface default".format(cmd_pfx)
            else:
                if non_passive != '' :
                    cmd_pfx = 'no' if config == 'yes' else ''

                cmd_str = "{} passive-interface {}".format(cmd_pfx, interface)
                if len(link_ip) >= (index + 1) and link_ip[index] != '' :
                    cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        command.append('exit')
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        psvif_type = True if non_passive != '' else False

        for index, interface in enumerate(interfaces):
            ip = link_ip[index] if len(link_ip) >= (index + 1) and link_ip[index] != '' else '0.0.0.0'
            index = int(get_subinterface_index(dut, interface))
            intf_name = get_phy_port(interface)
            if not cmd_pfx:
                url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
                if interface == 'default' or interface == '':
                    data = {"ospfv2": {"global": {"config": {"openconfig-ospfv2-ext:passive-interface-default": True, "openconfig-ospfv2-ext:enable": True}}}}
                else:
                    data = {"ospfv2": {"global": {"openconfig-ospfv2-ext:passive-interfaces": {"passive-interface": [{"config": {"name": intf_name, "address": ip, "non-passive": psvif_type, "subinterface" : index}, "subinterface" : index, "name": intf_name, "address": ip}]}}}}
                if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                        return False
            else:
                if interface == 'default' or interface == '':
                    url = rest_urls['config_ospfv2_passive_int_default'].format(vrf_str)
                else:
                    url = rest_urls['config_ospfv2_passive_int_non_default'].format(vrf_str, intf_name, index, ip)
                if not delete_rest(dut, http_method='delete', rest_url=url):
                        return False
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

    if cli_type in ['vtysh', 'klish']:
        result = st.config(dut, command, type=get_ospf_cli_type(dut, cli_type=cli_type), skip_error_check=skip_error)
        return validate_config_result(command, result, "")
    return True


def config_ospf_router_area_virtual_link(dut, area, ip_addr, params={}, vrf='default', instance='', config='yes', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    command = []
    cmd_pfx = '' if config == 'yes' else 'no'
    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf

    if cli_type in get_supported_ui_type_list():
        if len(params.keys()) != 0:
            ### Virtual link attributes config Not used in FT scripts,
            st.error("GNMI/Rest support not added for params")
            return False
        else:
            ni_obj = umf_ni.NetworkInstance(Name=vrf_str)
            ospf_proto_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
            if str(area) == '0':
                area = '0.0.0.0'
            area_obj = umf_ni.Area(Identifier=area, Protocol=ospf_proto_obj)
            result = area_obj.configure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config of Ospf Area:\n {}'.format(result.data))
                return False
            vl_obj = umf_ni.VirtualLink(RemoteRouterId=ip_addr, Area=area_obj)
            if config == 'yes':
                operation = Operation.CREATE
                result = vl_obj.configure(dut, operation=operation, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Config of Ospf Area Virtual Link: {}'.format(result.data))
                    return False
            else:
                result = vl_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: UnConfig of Ospf Area Virtual Link: {}'.format(result.data))
                    return False
            return True
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        #A.B.C.D authentication [<message-digest|null>]
        #A.B.C.D message-digest-key (1-255) md5 KEY|authentication-key AUTH_KEY>
        #A.B.C.D {hello-interval (1-65535)|retransmit-interval (1-65535)|transmit-delay (1-65535)|dead-interval (1-65535)

        if get_ospf_cli_type(dut, cli_type=cli_type) != 'klish' :
            cmd_str = "{} area {} virtual-link {}".format(cmd_pfx, area, ip_addr)
            if config == 'yes':
                if 'authentication' in params.keys():
                    if params['authentication'] == 'null':
                        cmd_str += " authentication null"
                        command.append(cmd_str)
                        cmd_str = " {} area {} virtual-link {}".format(cmd_pfx, area, ip_addr)
                    elif params['authentication'] == 'message-digest':
                        if 'message-digest-key' in params.keys():
                            if 'md_key_id' in params.keys() and 'md_key' in params.keys():
                                cmd_str += " authentication message-digest message-digest-key"
                                cmd_str += " {} md5 {}".format(params['md_key_id'], params['md_key'])
                                command.append(cmd_str)
                                cmd_str = " {} area {} virtual-link {}".format(cmd_pfx, area, ip_addr)

                if 'hello-interval' in params.keys():
                    cmd_str += " hello-interval {}".format(params['hello-interval'])
                if 'retransmit-interval' in params.keys():
                    cmd_str += " retransmit-interval {}".format(params['retransmit-interval'])
                if 'transmit-delay' in params.keys():
                    cmd_str += " transmit-delay {}".format(params['transmit-delay'])
                if 'dead-interval' in params.keys():
                    cmd_str += " dead-interval {}".format(params['dead-interval'])
            command.append(cmd_str)

        elif get_ospf_cli_type(dut, cli_type=cli_type) == 'klish' :
            if len (params.keys()) == 0 :
                cmd_str = "{} area {} virtual-link {}".format(cmd_pfx, area, ip_addr)
                command.append(cmd_str)
            else :
                 if 'authentication' in params.keys():
                     if params['authentication'] == '' :
                         cmd_str = "{} area {} virtual-link {} authentication".format(cmd_pfx, area, ip_addr)
                         command.append(cmd_str)
                     elif params['authentication'] == 'null':
                         cmd_str = "{} area {} virtual-link {} authentication null".format(cmd_pfx, area, ip_addr)
                         command.append(cmd_str)
                     elif params['authentication'] == 'message-digest':
                         cmd_str = "{} area {} virtual-link {} authentication message-digest".format(cmd_pfx, area, ip_addr)
                         command.append(cmd_str)

                 if 'authentication-key' in params.keys():
                     if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                         cmd_str = "{} area {} virtual-link {} authentication-key".format(cmd_pfx, area, ip_addr)
                         command.append(cmd_str)
                     else:
                         cmd_str = "{} area {} virtual-link {}".format(cmd_pfx, area, ip_addr)
                         cmd_str += " authentication-key {}".format(params['authentication-key'])
                         command.append(cmd_str)

                 if 'message-digest-key' in params.keys():
                     if 'md_key_id' in params.keys() and 'md_key' in params.keys():
                         cmd_str = "{} area {} virtual-link {}".format(cmd_pfx, area, ip_addr)
                         if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                             cmd_str += " message-digest-key {} md5".format(params['md_key_id'])
                             command.append(cmd_str)
                         else:
                             cmd_str += " message-digest-key {} md5 {}".format(params['md_key_id'], params['md_key'])
                         command.append(cmd_str)

                 if 'hello-interval' in params.keys():
                     cmd_str = "{} area {} virtual-link {}".format(cmd_pfx, area, ip_addr)
                     if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                         cmd_str += " hello-interval"
                     else:
                         cmd_str += " hello-interval {}".format( params['hello-interval'])
                     command.append(cmd_str)

                 if 'retransmit-interval' in params.keys():
                     cmd_str = "{} area {} virtual-link {}".format(cmd_pfx, area, ip_addr)
                     if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                         cmd_str += " retransmit-interval"
                     else :
                         cmd_str += " retransmit-interval {}".format( params['retransmit-interval'])
                     command.append(cmd_str)

                 if 'transmit-delay' in params.keys():
                     cmd_str = "{} area {} virtual-link {}".format(cmd_pfx, area, ip_addr)
                     if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                         cmd_str += " transmit-delay"
                     else:
                         cmd_str += " transmit-delay {}".format( params['transmit-delay'])
                     command.append(cmd_str)

                 if 'dead-interval' in params.keys():
                     cmd_str = "{} area {} virtual-link {}".format(cmd_pfx, area, ip_addr)
                     if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                         cmd_str += " dead-interval"
                     else:
                         cmd_str += " dead-interval {}".format( params['dead-interval'])
                     command.append(cmd_str)

        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            data = {"ospfv2": {"openconfig-network-instance:areas": {"area": [{"identifier": area, "virtual-links": {"virtual-link": [{"config": {"openconfig-ospfv2-ext:enable": True, "remote-router-id": ip_addr}, "remote-router-id": ip_addr}]}}]}}}
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            url = rest_urls['config_ospfv2_area_virtual_link'].format(vrf_str, area, ip_addr)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


# ------------------ OSPF Interface command APIs -------------------------------------

def get_interface_cmd(dut, interface, vrf='default', cli_type=''):

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    vrf_str = ''
    if cli_type == 'klish':
        if not is_a_single_intf(interface):
            interface = "range {}".format(interface)
        else:
            intf_info = get_interface_number_from_name(interface)
            if isinstance(intf_info, dict):
                interface = "{} {}".format(intf_info["type"], intf_info["number"])
    elif cli_type == 'vtysh':
        interface=get_intf_short_name(interface)
        if vrf != 'default' and vrf != '':
            vrf_str = "vrf {}".format(vrf)

    if vrf_str != '' :
        intf_cmd = "interface {} {}".format(interface, vrf_str)
    else :
        intf_cmd = "interface {}".format(interface)

    return intf_cmd


def get_interface_rest_uri(dut, interface, uri_ext='base_unconfig', index=0, if_addr=None):
    """
    Author:
    :param dut:
    :param interface: Physical or logical interface name
    :param uri_ext: This will be concating to uri which is defined in /datastore/rest_urls
    :param index: index value used in rest uri
    :param if_addr: ip address used in rest uri
    :return:
    :rtype:
    """
    # config_ospfv2_interface_mode: "/openconfig-interfaces:interfaces/interface={}/subinterfaces/subinterface={}/openconfig-if-ip:ipv4/openconfig-ospfv2-ext:ospfv2/if-addresses={}/config"
    if_addr = if_addr if if_addr else '0.0.0.0'
    rest_urls = st.get_datastore(dut, "rest_urls")
    index = int(get_subinterface_index(dut, interface))
    interface = get_phy_port(interface)

    if 'Vlan' in interface:
        uri_id = 'config_ospfv2_interface_vlan_{}'.format(uri_ext)
    else:
        uri_id = 'config_ospfv2_interface_{}'.format(uri_ext)
    if uri_ext == 'base':
        if 'Vlan' in interface:
            rest_uri = rest_urls[uri_id].format(interface)
        else:
            rest_uri = rest_urls[uri_id].format(interface, index)
    else:
        if 'Vlan' in interface:
            rest_uri = rest_urls[uri_id].format(interface, if_addr)
        else:
            rest_uri = rest_urls[uri_id].format(interface, index, if_addr)
    return rest_uri


def config_interface_ip_ospf_area(dut, interfaces, ospf_area, link_ip='', vrf='', instance='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.UPDATE
            else:
                index = int(get_subinterface_index(dut, interface))
                interface = get_phy_port(interface)
                intf_obj = umf_intf.Interface(Name=interface)
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                gnmi_op = Operation.CREATE
                ospf_intf_obj.AreaId = ospf_area
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.AreaId
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf Area at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf, cli_type=cli_type)
            command.append(cmd_str)
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str = "{} ip ospf area".format(cmd_pfx)
            else :
                cmd_str = "{} ip ospf area {}".format(cmd_pfx, ospf_area)

            if ip:
                cmd_str += " {}".format(ip)
            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='area_id', if_addr=ip)
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip)
                if_addr = ip if ip else '0.0.0.0'
                if "Vlan" in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"area-id": ospf_area, "address": if_addr}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"area-id": ospf_area, "address": if_addr}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_authentication(dut, interfaces, msg_digest='', link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.CREATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                if msg_digest != '':
                    ospf_intf_obj.AuthenticationType = 'MD5HMAC'
                else:
                    ospf_intf_obj.AuthenticationType = 'TEXT'
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.AuthenticationType
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf authentication type at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)
            cmd_str = "{} ip ospf authentication".format(cmd_pfx)
            if msg_digest != '' :
                cmd_str += " {}".format(msg_digest)
            if ip:
                cmd_str += " {}".format(link_ip[index])
            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip)
                if_addr = ip if ip else '0.0.0.0'
                index = int(get_subinterface_index(dut, interface))
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"authentication-type": "TEXT", "address": if_addr}, "address": if_addr}]}}}}
                else:
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"authentication-type": "TEXT", "address": if_addr}, "address": if_addr}]}}}]}
                if msg_digest != '' :
                    if 'Vlan' in interface:
                        data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"authentication-type": "MD5HMAC", "address": if_addr}, "address": if_addr}]}}}}
                    else:
                        data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"authentication-type": "MD5HMAC", "address": if_addr}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='auth_type', if_addr=ip)
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_authentication_key(dut, interfaces, auth_key, link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.CREATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                ospf_intf_obj.AuthenticationKey = auth_key
                ospf_intf_obj.AuthenticationKeyEncrypted = False
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Config of Ospf Authentication Key at interface: {}'.format(result.data))
                    return False
            else:
                result_flag = True
                target_attr = ospf_intf_obj.AuthenticationKeyEncrypted
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                result_flag = result_flag and result.ok()
                target_attr = ospf_intf_obj.AuthenticationKey
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
                result_flag = result_flag and result.ok()
                if not result_flag:
                    st.log('test_step_failed: UnConfig of Ospf Authentication Key at interface: {}'.format(result.data))
                    return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str = "{} ip ospf authentication-key".format(cmd_pfx)
            else :
                cmd_str = "{} ip ospf authentication-key {}".format(cmd_pfx, auth_key)

            if ip:
                cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='auth_key', if_addr=ip)
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip)
                if_addr = ip if ip else '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"authentication-key": auth_key, "authentication-key-encrypted": False, "address": if_addr}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"authentication-key": auth_key, "address": if_addr}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_authentication_md_key(dut, interfaces, key_id, auth_key, link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            key_id = integer_parse(key_id)
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.CREATE
                md_auth_obj = umf_intf.RoutedVlanMdAuthentication(AuthenticationKeyId=key_id,RoutedVlanIfAddresses=ospf_intf_obj)
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE
                md_auth_obj = umf_intf.SubinterfaceMdAuthentication(AuthenticationKeyId=key_id,SubinterfaceIfAddresses=ospf_intf_obj)

            if config == 'yes':
                md_auth_obj.AuthenticationMd5Key = auth_key
                md_auth_obj.AuthenticationKeyEncrypted = False
                result = md_auth_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: Config of Ospf MD Authentication Key at interface: {}'.format(
                        result.data))
                    return False
            else:
                result = md_auth_obj.unConfigure(dut, cli_type=cli_type)
                if not result.ok():
                    st.log('test_step_failed: UnConfig of Ospf MD Authentication Key at interface: {}'.format(
                        result.data))
                    return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str = "{} ip ospf message-digest-key {} md5".format(cmd_pfx, key_id)
            else :
                cmd_str = "{} ip ospf message-digest-key {} md5 {}".format(cmd_pfx, key_id, auth_key)

            if ip:
                cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip)
                if_addr = ip if ip else '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"md-authentications": {"md-authentication": [{"config": {"authentication-md5-key": auth_key, "authentication-key-encrypted": False, "authentication-key-id": integer_parse(key_id)}, "authentication-key-id": integer_parse(key_id)}]}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"md-authentications": {"md-authentication": [{"config": {"authentication-md5-key": auth_key, "authentication-key-encrypted": False, "authentication-key-id": integer_parse(key_id)}, "authentication-key-id": integer_parse(key_id)}]}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                rest_urls = st.get_datastore(dut, "rest_urls")
                index = 0
                if_addr = ip if ip else '0.0.0.0'
                if 'Vlan' in interface:
                    rest_url = rest_urls['config_ospfv2_interface_vlan_auth_key_id'].format(interface, if_addr, key_id)
                else:
                    rest_url = rest_urls['config_ospfv2_interface_md_auth_key_id'].format(interface, index, if_addr, key_id)
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_bfd(dut, interfaces, vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    for interface in interfaces:

        if cli_type in get_supported_ui_type_list():
            if_addr = '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.UPDATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                ospf_intf_obj.Enabled = True
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                for target_attr in [ospf_intf_obj.Enabled, ospf_intf_obj.BfdProfile]:
                    result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf BFD at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf, cli_type=cli_type)
            command.append(cmd_str)
            cmd_str = " {} ip ospf bfd".format(cmd_pfx)
            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='bfd')
            rest_url_prof = get_interface_rest_uri(dut, interface, uri_ext='bfd_profile')
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base')
                if_addr = '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"address": if_addr}, "address": if_addr,  "enable-bfd" : { "config" : {"enabled": True }}}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"address": if_addr}, "address": if_addr, "enable-bfd" : { "config" : {"enabled": True }}}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                for url in [rest_url_prof, rest_url]:
                    if not delete_rest(dut, http_method='delete', rest_url=url):
                        return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True

def config_interface_ip_ospf_bfd_profile(dut, interfaces, vrf='', config='yes', bfd_profile='', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    for interface in interfaces:

        if cli_type in get_supported_ui_type_list():
            if_addr = '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.CREATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                if bfd_profile == '':
                    st.error("Missing Mandatory Arg: bfd_profile")
                    return False
                ospf_intf_obj.BfdProfile = bfd_profile
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.BfdProfile
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf BFD profile at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf, cli_type=cli_type)
            command.append(cmd_str)
            if not cmd_pfx:
                cmd_str = "ip ospf bfd profile {}".format(bfd_profile)
            else:
                cmd_str = "{} ip ospf bfd profile".format(cmd_pfx)
            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='bfd_profile')
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base')
                if_addr = '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"address": if_addr}, "address": if_addr, "enable-bfd" : { "config" : {"bfd-profile": bfd_profile}}}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"address": if_addr}, "address": if_addr, "enable-bfd" : { "config" : {"bfd-profile": bfd_profile}}}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True

def config_interface_ip_ospf_cost(dut, interfaces, cost, link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.CREATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                ospf_intf_obj.Metric = integer_parse(cost)
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.Metric
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf Cost at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)

            if check_if_klish_unconfig(dut, cmd_pfx, cli_type) :
                cmd_str = "{} ip ospf cost".format(cmd_pfx)
            else :
                cmd_str = "{} ip ospf cost {}".format(cmd_pfx, cost)

            if ip:
                cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='metric', if_addr=ip)
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip )
                if_addr = ip if ip else '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"metric": integer_parse(cost), "address": if_addr}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"metric": integer_parse(cost), "address": if_addr}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_dead_interval(dut, interfaces, interval, link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    # (1-65535)  Seconds
    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.CREATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                ospf_intf_obj.DeadInterval = integer_parse(interval)
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.DeadInterval
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf dead-interval at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)

            if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                cmd_str = "{} ip ospf dead-interval".format(cmd_pfx)
            else:
                cmd_str = "{} ip ospf dead-interval {}".format(cmd_pfx, interval)

            if ip:
                cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='dead_interval', if_addr=ip)
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip)
                if_addr = ip if ip else '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"dead-interval": integer_parse(interval), "address": if_addr, "dead-interval-minimal": False}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"dead-interval": integer_parse(interval), "address": if_addr, "dead-interval-minimal": False}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_dead_interval_multiplier(dut, interfaces, multiplier, link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    # 1-10
    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)

            if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                cmd_str = "{} ip ospf dead-interval minimal hello-multiplier".format(cmd_pfx)
            else:
                cmd_str = "{} ip ospf dead-interval minimal hello-multiplier {}".format(cmd_pfx, multiplier)

            if ip:
                cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='dead_interval_mimimal', if_addr=ip)
            if_addr = ip if ip else '0.0.0.0'
            if not cmd_pfx:
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"address": if_addr, "hello-multiplier": integer_parse(multiplier), "dead-interval-minimal": True}, "address": if_addr}]}}}}
                else:
                    data = {"openconfig-ospfv2-ext:dead-interval-minimal": integer_parse(multiplier)}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_hello_interval(dut, interfaces, interval, link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.CREATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                ospf_intf_obj.HelloInterval = integer_parse(interval)
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.HelloInterval
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf hello-interval at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)

            if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                cmd_str = "{} ip ospf hello-interval".format(cmd_pfx)
            else:
                cmd_str = "{} ip ospf hello-interval {}".format(cmd_pfx, interval)

            if ip:
                cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='hello_interval', if_addr=ip)
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip)
                if_addr = ip if ip else '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"hello-interval": integer_parse(interval), "address": if_addr}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"hello-interval": integer_parse(interval), "address": if_addr}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_mtu_ignore(dut, interfaces, link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.UPDATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                ospf_intf_obj.MtuIgnore = True
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.MtuIgnore
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf mtu-ignore at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)

            cmd_str = "{} ip ospf mtu-ignore".format(cmd_pfx)

            if ip:
                cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='mtu_ignore', if_addr=ip)
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip)
                if_addr = ip if ip else '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"mtu-ignore": True, "address": if_addr}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"mtu-ignore": True, "address": if_addr}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_network_type(dut, interfaces, nw_type, vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    for interface in interfaces:
        if cli_type in get_supported_ui_type_list():
            if_addr = '0.0.0.0'
            network_type = {'point-to-point': 'POINT_TO_POINT_NETWORK', 'broadcast': 'BROADCAST_NETWORK'}
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.CREATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                ospf_intf_obj.NetworkType = network_type[nw_type]
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.NetworkType
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf network-type at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)

            #nwtype broadcast|non-broadcast|point-to-multipoint|point-to-point
            if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                cmd_str = "{} ip ospf network".format(cmd_pfx)
            else :
                cmd_str = "{} ip ospf network {}".format(cmd_pfx, nw_type)

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            network_type = {'point-to-point': 'POINT_TO_POINT_NETWORK', 'broadcast': 'BROADCAST_NETWORK'}
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='nw_type')
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base')
                if_addr = '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"address": if_addr, "network-type": network_type[nw_type]}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"address": if_addr, "network-type": network_type[nw_type]}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_priority(dut, interfaces, priority, link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.UPDATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                ospf_intf_obj.Priority = integer_parse(priority)
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.Priority
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf Priority at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)

            if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                cmd_str = "{} ip ospf priority".format(cmd_pfx)
            else:
                cmd_str = "{} ip ospf priority {}".format(cmd_pfx, priority)

            if ip:
                cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='priority', if_addr=ip)
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip)
                if_addr = ip if ip else '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"priority": integer_parse(priority), "address": if_addr}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"priority": integer_parse(priority), "address": if_addr}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_retransmit_interval(dut, interfaces, interval, link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.UPDATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                ospf_intf_obj.RetransmissionInterval = integer_parse(interval)
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.RetransmissionInterval
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf retransmit-interval at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)

            if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                cmd_str = "{} ip ospf retransmit-interval".format(cmd_pfx)
            else:
                cmd_str = "{} ip ospf retransmit-interval {}".format(cmd_pfx, interval)

            if ip:
                cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='rtx_interval', if_addr=ip)
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip)
                if_addr = ip if ip else '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"retransmission-interval": integer_parse(interval), "address": if_addr}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"retransmission-interval": integer_parse(interval), "address": if_addr}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_transmit_delay(dut, interfaces, delay, link_ip='', vrf='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(link_ip, list):
        link_ip = [link_ip]

    for index, interface in enumerate(interfaces):
        ip = None
        if len(link_ip) >= (index + 1) and link_ip[index] != '':
            ip = link_ip[index]

        if cli_type in get_supported_ui_type_list():
            if_addr = ip if ip else '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_addr, Interface=intf_obj)
                gnmi_op = Operation.UPDATE
            else:
                index = int(get_subinterface_index(dut, interface))
                sub_intf_obj = umf_intf.Subinterface(Index=index, Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_addr, Subinterface=sub_intf_obj)
                gnmi_op = Operation.CREATE

            if config == 'yes':
                ospf_intf_obj.TransmitDelay = integer_parse(delay)
                result = ospf_intf_obj.configure(dut, operation=gnmi_op, cli_type=cli_type)
            else:
                target_attr = ospf_intf_obj.TransmitDelay
                result = ospf_intf_obj.unConfigure(dut, target_attr=target_attr, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: Config/UnConfig of Ospf transmit-delay at interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface, vrf)
            command.append(cmd_str)

            if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
                cmd_str = "{} ip ospf transmit-delay".format(cmd_pfx)
            else:
                cmd_str = "{} ip ospf transmit-delay {}".format(cmd_pfx, delay)

            if ip:
                cmd_str += " {}".format(link_ip[index])

            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='tx_interval', if_addr=ip)
            if not cmd_pfx:
                rest_url = get_interface_rest_uri(dut, interface, uri_ext='base', if_addr=ip)
                if_addr = ip if ip else '0.0.0.0'
                if 'Vlan' in interface:
                    data = {"openconfig-vlan:routed-vlan": {"openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"transmit-delay": integer_parse(delay), "address": if_addr}, "address": if_addr}]}}}}
                else:
                    index = int(get_subinterface_index(dut, interface))
                    data = {"openconfig-interfaces:subinterface": [{"index": index, "openconfig-if-ip:ipv4": {"openconfig-ospfv2-ext:ospfv2": {"if-addresses": [{"config": {"transmit-delay": integer_parse(delay), "address": if_addr}, "address": if_addr}]}}}]}
                if not config_rest(dut, http_method=cli_type, rest_url=rest_url, json_data=data):
                    return False
            else:
                if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                    return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_interface_ip_ospf_interface(dut, interfaces, cli_type=''):

    command = []
    cmd_pfx = 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    #cli_type = force_cli_type_to_klish(cli_type=cli_type)
    if cli_type == 'vtysh':
        st.log("This commmand is needed only for KLISH CLI.")
        return True

    ### Processing kwargs
    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    st.log("{} - no ip ospf interface received for {}".format(dut, interfaces))
    for interface in interfaces:
        if cli_type in get_supported_ui_type_list():
            index = int(get_subinterface_index(dut, interface))
            if_add = '0.0.0.0'
            intf_obj = umf_intf.Interface(Name=interface)
            if 'Vlan' in interface:
                ospf_intf_obj = umf_intf.RoutedVlanIfAddresses(Address=if_add,Interface=intf_obj)
            else:
                sub_intf_obj = umf_intf.Subinterface(Index=index,Interface=intf_obj)
                ospf_intf_obj = umf_intf.SubinterfaceIfAddresses(Address=if_add, Subinterface=sub_intf_obj)

            if cmd_pfx != 'no':
                result = ospf_intf_obj.configure(dut, cli_type=cli_type)
            else:
                result = ospf_intf_obj.unConfigure(dut, cli_type=cli_type)
            if not result.ok():
                st.log('test_step_failed: UnConfig of Ospf interface: {}'.format(result.data))
                return False
        elif cli_type in ['vtysh', 'klish']:
            cmd_str = get_interface_cmd(dut, interface)
            command.append(cmd_str)
            cmd_str = " {} ip ospf interface".format(cmd_pfx)
            command.append(cmd_str)
        elif cli_type in ["rest-patch", "rest-put"]:
            rest_url = get_interface_rest_uri(dut, interface, uri_ext='delete')
            if not delete_rest(dut, http_method='delete', rest_url=rest_url):
                return False
        else:
            st.error("Invalid UI-Type: {} provided".format(cli_type))
            return False

    if cli_type in ['vtysh', 'klish']:
        command.append('exit')
        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    return True


def config_ospf_router_default_information_extended(dut, dinfo_type='', dinfo_param='metric', dinfo_value='10', metric_type='2', vrf='default', instance='', config='yes', cli_type=''):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    vrf_str = 'default' if vrf == 'default' or vrf == '' else vrf

    if cli_type in get_supported_ui_type_list():
        if dinfo_param == 'metric':
            if config_ospf_router_default_information(dut, dinfo_type=dinfo_param, dinfo_value=dinfo_value, vrf=vrf,
                                                      instance=instance, config=config, cli_type=cli_type):
                return config_ospf_router_default_information(dut, dinfo_type='metric-type', dinfo_value=metric_type,
                                                              vrf=vrf,
                                                              instance=instance, config=config, cli_type=cli_type)
            else:
                return False
        elif dinfo_param == 'metric-type':
            return config_ospf_router_default_information(dut, dinfo_type=dinfo_param, dinfo_value=metric_type, vrf=vrf,
                                                          instance=instance, config=config, cli_type=cli_type)
        elif dinfo_param == 'route-map':
            return config_ospf_router_default_information(dut, dinfo_type=dinfo_param, dinfo_value=metric_type, vrf=vrf,
                                                          instance=instance, config=config, cli_type=cli_type)
        else:
            st.log("Invalid parameter {} {}".format(dinfo_type, dinfo_value))
            return False
        return True
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = get_ospf_router_cmd(vrf, instance)
        command.append(cmd_str)

        # Need to extended the below to configure all the posible CLIS, as per the requirement
        cmd_str = "{} default-information originate ".format(cmd_pfx)
        if dinfo_type == 'always':
           cmd_str += "always "

        if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
            if dinfo_param == 'metric':
                cmd_str += "{} metric-type".format(dinfo_param)
            elif dinfo_param == 'metric-type':
                cmd_str += "{}".format(dinfo_param)
            elif dinfo_param == 'route-map':
                cmd_str += "{}".format(dinfo_param)
            else:
                st.log("Invalid parameter {} {}".format(dinfo_type, dinfo_value))
                return False
        else:
            if dinfo_param == 'metric':
               cmd_str += "{} {} metric-type {}".format(dinfo_param, dinfo_value, metric_type)
            elif dinfo_param == 'metric-type':
                cmd_str += "{} {}".format(dinfo_param, metric_type)
            elif dinfo_param == 'route-map':
                cmd_str += "{} {}".format(dinfo_param, dinfo_value)
            else:
               st.log("Invalid parameter {} {}".format(dinfo_type, dinfo_value))
               return False
        command.append(cmd_str)
        command.append('exit')

        result = st.config(dut, command, type=cli_type)
        return validate_config_result(command, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        rest_urls = st.get_datastore(dut, "rest_urls")
        if metric_type: metric_type = "TYPE_" + str(metric_type)
        route_type = "DEFAULT_ROUTE"
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            if dinfo_param == 'metric':
                data = {"ospfv2": {"global": {"openconfig-ospfv2-ext:route-distribution-policies": {"distribute-list": [{"config": {"direction": "IMPORT", "protocol": route_type, "openconfig-ospfv2-ext:metric": integer_parse(dinfo_value), "openconfig-ospfv2-ext:metric-type": metric_type, "openconfig-ospfv2-ext:always": True}, "direction": "IMPORT", "protocol": route_type}]}}}}
            elif dinfo_param == 'metric-type':
                data = {"ospfv2": {"global": {"openconfig-ospfv2-ext:route-distribution-policies": {"distribute-list": [{"config": {"direction": "IMPORT", "protocol": route_type, "openconfig-ospfv2-ext:always": True, "openconfig-ospfv2-ext:metric-type": metric_type}, "direction": "IMPORT", "protocol": route_type}]}}}}
            elif dinfo_param == 'route-map':
                data = {"ospfv2": {"global": {"openconfig-ospfv2-ext:route-distribution-policies": {"distribute-list": [{"config": {"direction": "IMPORT", "protocol": route_type, "openconfig-ospfv2-ext:route-map": dinfo_value, "openconfig-ospfv2-ext:always": True}, "direction": "IMPORT", "protocol": route_type}]}}}}
            else:
                st.log("Invalid parameter {} {}".format(dinfo_type, dinfo_value))
                return False
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if dinfo_param == 'metric':
                url = rest_urls['config_ospfv2_route_redistribute_metric_type'].format(vrf_str, route_type)
            elif dinfo_param == 'metric-type':
                url = rest_urls['config_ospfv2_route_redistribute_metric_type'].format(vrf_str, route_type)
            else:
                url = rest_urls['config_ospfv2_route_redistribute_route_map'].format(vrf_str, route_type)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
            url = rest_urls['config_ospfv2_route_default_info_originate_always'].format(vrf_str, route_type)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False


# ------------------ OSPF Logging config command APIs -------------------------------------

def config_debug_ospf_packet(dut, pkt_types, send=True, detail=False, instance='', config='yes'):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    # pkt_types - hello|dd|ls-request|ls-update|ls-ack|all
    if not isinstance(pkt_types, list):
        if pkt_types == '':
            pkt_types = ['all']
        else:
            pkt_types = [pkt_types]

    for pkt_type in pkt_types:
        cmd_str  = " {} debug ospf {} packet {} ".format(cmd_pfx, instance, pkt_type)
        cmd_str += " send " if send else " recv "
        cmd_str += " detail " if detail else ""
        command.append(cmd_str)

    result = st.config(dut, command, type='vtysh')
    return validate_config_result(command, result, "")


def config_debug_ospf_ism(dut, ism_types, instance='', config='yes'):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    # ism_types - ''|status|events|timers
    if not isinstance(ism_types, list):
        if ism_types == 'all':
            ism_types = [ 'status', 'events', 'timers' ]
        else:
            ism_types = [ism_types]

    for ism_type in ism_types:
        cmd_str  = " {} debug ospf {} ism {} ".format(cmd_pfx, instance, ism_type)
        command.append(cmd_str)

    result = st.config(dut, command, type='vtysh')
    return validate_config_result(command, result, "")


def config_debug_ospf_nsm(dut, nsm_types, instance='', config='yes'):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    # nsm_types - ''|status|events|timers
    if not isinstance(nsm_types, list):
        if nsm_types == 'all':
            nsm_types = [ 'status', 'events', 'timers' ]
        else:
            nsm_types = [nsm_types]

    for nsm_type in nsm_types:
        cmd_str  = " {} debug ospf {} nsm {} ".format(cmd_pfx, instance, nsm_type)
        command.append(cmd_str)

    result = st.config(dut, command, type='vtysh')
    return validate_config_result(command, result, "")


def config_debug_ospf_lsa(dut, lsa_types, instance='', config='yes'):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    # lsa_types - ''|generate|flooding|refresh
    if not isinstance(lsa_types, list):
        if lsa_types == 'all':
            lsa_types = [ 'generate','flooding','refresh' ]
        else:
            lsa_types = [lsa_types]

    for lsa_type in lsa_types:
        cmd_str  = " {} debug ospf {} lsa {} ".format(cmd_pfx, instance, lsa_type)
        command.append(cmd_str)

    result = st.config(dut, command, type='vtysh')
    return validate_config_result(command, result, "")


def config_debug_ospf_zebra(dut, zebra_types, instance='', config='yes'):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    # zebra_types - ''|interface|redistribute
    if not isinstance(zebra_types, list):
        if zebra_types == 'all':
            zebra_types = [ 'interface', 'redistribute' ]
        else:
            zebra_types = [zebra_types]

    for zebra_type in zebra_types:
        cmd_str  = " {} debug ospf {} zebra {} ".format(cmd_pfx, instance, zebra_type)
        command.append(cmd_str)

    result = st.config(dut, command, type='vtysh')
    return validate_config_result(command, result, "")


def config_debug_ospf_event(dut, instance='', config='yes'):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cmd_str  = " {} debug ospf {} event ".format(cmd_pfx, instance)
    command.append(cmd_str)

    result = st.config(dut, command, type='vtysh')
    return validate_config_result(command, result, "")


def config_debug_ospf_nssa(dut, instance='', config='yes'):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cmd_str  = " {} debug ospf {} nssa ".format(cmd_pfx, instance)
    command.append(cmd_str)

    result = st.config(dut, command, type='vtysh')
    return validate_config_result(command, result, "")


def config_debug_ospf_all(dut, instance='', config='no'):

    command = []
    cmd_pfx = '' if config == 'yes' else 'no'

    cmd_str  = " {} debug ospf {}".format(cmd_pfx, instance)
    command.append(cmd_str)

    result = st.config(dut, command, type='vtysh')
    return validate_config_result(command, result, "")


# ------------------ OSPF Misc command APIs -------------------------------------

def redistribute_into_ospf(dut, route_type, vrf_name = 'default', config='yes', metric='', metric_type='', route_map='', cli_type=''):
    """

  ` :param dut:
    :param route_type:
    :param vrf_name:
    :param config:
    :param metric:
    :param metric_type:
    :param route_map:
    :param cli_type:
    :return:
    """

    command_str = []

    cmd_pfx = '' if config == 'yes' else 'no'
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if cli_type in get_supported_ui_type_list():
        config_ospf_router_redistribute(dut, redist_type=route_type, metric=metric, metric_type=metric_type,
                                        routemap=route_map, vrf=vrf_name, config=config, cli_type=cli_type)
    elif cli_type in ['vtysh', 'klish']:
        command = get_ospf_router_cmd(vrf_name)
        command_str.append(command)
        if check_if_klish_unconfig(dut, cmd_pfx, cli_type):
            if metric_type != '' and metric != '' and route_map != '':
                command = "{} redistribute {} metric metric-type route-map".format(cmd_pfx, route_type)
            elif metric != '' and route_map != '':
                command = "{} redistribute {} metric route-map".format(cmd_pfx, route_type)
            elif metric_type != '' and route_map != '':
                command = "{} redistribute {} metric_type route-map".format(cmd_pfx, route_type)
            elif metric_type != '' and metric != '':
                command = "{} redistribute {} metric metric-type".format(cmd_pfx, route_type)
            elif metric != '':
                command = "{} redistribute {} metric".format(cmd_pfx, route_type)
            elif metric_type != '':
                command = "{} redistribute {} metric_type".format(cmd_pfx, route_type)
            elif route_map != '':
                command = "{} redistribute {} route-map".format(cmd_pfx, route_type)
            else:
                command = "{} redistribute {}".format(cmd_pfx, route_type)
        else:
            if metric_type != '' and metric != '' and route_map != '':
                command = "{} redistribute {} metric {} metric-type {} route-map {}".format(cmd_pfx, route_type, metric, metric_type, route_map)
            elif metric != '' and route_map != '':
                command = "{} redistribute {} metric {} route-map {}".format(cmd_pfx, route_type, metric, route_map)
            elif metric_type != '' and route_map != '':
                command = "{} redistribute {} metric_type {} route-map {}".format(cmd_pfx, route_type, metric_type, route_map)
            elif metric_type != '' and metric != '':
                command = "{} redistribute {} metric {} metric-type {}".format(cmd_pfx, route_type, metric, metric_type)
            elif metric != '':
                command = "{} redistribute {} metric {}".format(cmd_pfx, route_type, metric)
            elif metric_type != '':
                command = "{} redistribute {} metric_type {}".format(cmd_pfx, route_type, metric_type)
            elif route_map != '':
                command = "{} redistribute {} route-map {}".format(cmd_pfx, route_type, route_map)
            else:
                command = "{} redistribute {}".format(cmd_pfx, route_type)
        command_str.append(command)
        command_str.append('exit')

        result = st.config(dut, command_str, type=get_ospf_cli_type(dut, cli_type=cli_type))
        return validate_config_result(command_str, result, "")
    elif cli_type in ["rest-patch", "rest-put"]:
        vrf_str = 'default' if vrf_name == 'default' or vrf_name == '' else vrf_name
        rest_urls = st.get_datastore(dut, "rest_urls")
        route_type = route_type.upper()
        if route_type == 'CONNECTED': route_type = 'DIRECTLY_CONNECTED'
        if metric_type: metric_type = "TYPE_" + str(metric_type)
        if metric: metric = integer_parse(metric)
        if not cmd_pfx:
            url = rest_urls['config_ospfv2_global_base'].format(vrf_str)
            data = {'ospfv2': {'global': {'openconfig-ospfv2-ext:route-distribution-policies': {'distribute-list': [{'protocol': route_type, 'direction': 'IMPORT', 'config': {'direction': 'IMPORT', 'protocol': route_type}}]}}}}
            if metric_type != '' and metric != '' and route_map != '':
                dict1 = {"openconfig-ospfv2-ext:metric": metric, "openconfig-ospfv2-ext:metric-type": metric_type, "openconfig-ospfv2-ext:route-map": route_map}
                data['ospfv2']['global']['openconfig-ospfv2-ext:route-distribution-policies']['distribute-list'][0]['config'].update(dict1)
            elif metric != '' and route_map != '':
                dict1 = {"openconfig-ospfv2-ext:metric": metric, "openconfig-ospfv2-ext:route-map": route_map}
                data['ospfv2']['global']['openconfig-ospfv2-ext:route-distribution-policies']['distribute-list'][0]['config'].update(dict1)
            elif metric_type != '' and route_map != '':
                dict1 = {"openconfig-ospfv2-ext:metric-type": metric_type, "openconfig-ospfv2-ext:route-map": route_map}
                data['ospfv2']['global']['openconfig-ospfv2-ext:route-distribution-policies']['distribute-list'][0]['config'].update(dict1)
            elif metric_type != '' and metric != '':
                dict1 = {"openconfig-ospfv2-ext:metric": metric, "openconfig-ospfv2-ext:metric-type": metric_type}
                data['ospfv2']['global']['openconfig-ospfv2-ext:route-distribution-policies']['distribute-list'][0]['config'].update(dict1)
            elif metric != '':
                dict1 = {"openconfig-ospfv2-ext:metric": metric}
                data['ospfv2']['global']['openconfig-ospfv2-ext:route-distribution-policies']['distribute-list'][0]['config'].update(dict1)
            elif metric_type != '':
                dict1 = {"openconfig-ospfv2-ext:metric-type": metric_type}
                data['ospfv2']['global']['openconfig-ospfv2-ext:route-distribution-policies']['distribute-list'][0]['config'].update(dict1)
            elif route_map != '':
                dict1 = {"openconfig-ospfv2-ext:route-map": route_map}
                data['ospfv2']['global']['openconfig-ospfv2-ext:route-distribution-policies']['distribute-list'][0]['config'].update(dict1)
            if not config_rest(dut, http_method=cli_type, rest_url=url, json_data=data):
                return False
        else:
            if metric_type != '':
                url = rest_urls['config_ospfv2_route_redistribute_metric_type'].format(vrf_str, route_type)
            elif metric != '':
                url = rest_urls['config_ospfv2_route_redistribute_metric'].format(vrf_str,route_type)
            else:
                url = rest_urls['config_ospfv2_route_redistribute_route_map'].format(vrf_str, route_type)
            if not delete_rest(dut, http_method='delete', rest_url=url):
                return False
        return True
    else:
        st.error("Invalid UI-Type: {} provided".format(cli_type))
        return False

# ------------------ OSPF clear command APIs -------------------------------------

def clear_interface_ip_ospf(dut, interfaces, vrf='', cli_type=''):

    command = []

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    if cli_type in ["rest-patch", "rest-put"]+get_supported_ui_type_list(): cli_type = 'klish'

    cmd_str_base = 'clear ip ospf'

    if cli_type != 'klish' :
        cmd_str_base = "do {}".format(cmd_str_base)

    if vrf != '' :
        cmd_str_base += " vrf {}".format(vrf)

    for interface in interfaces:
        if interface == 'all' :
            cmd_str = "{} interface".format(cmd_str_base)
        else :
            cmd_str = "{} interface {}".format(cmd_str_base, interface)
        command.append(cmd_str)

    result = st.config(dut, command, type=cli_type)

    return validate_config_result(command, result, "")



# ------------------ OSPF Show command APIs -------------------------------------


def show_dut_ospf_cmd_logs(dut):
    st.show(dut,"write terminal", type='vtysh')
    st.show(dut, "show interface brief", type='vtysh')
    st.show(dut, "show ip ospf vrf ", type='vtysh')
    st.show(dut, "show ip ospf vrf all", type='vtysh')
    st.show(dut, "show ip ospf vrf all neighbor", type='vtysh')
    st.show(dut, "show ip ospf vrf all interface", type='vtysh')
    st.show(dut, "show ip ospf vrf all route", type='vtysh')
    st.show(dut, "show ip route vrf all", type='vtysh')
    st.show(dut, "show ip ospf vrf all database", type='vtysh')
    st.show(dut, "show ip ospf vrf all database summary", type='vtysh')
    # Some times the below CLI is causing very huge o/p dump in the failure scenario, need to debug and uncomment this.
    # st.show(dut, "show ip ospf vrf all database external", type='vtysh')
    st.show(dut, "show ip ospf vrf all database network", type='vtysh')
    st.show(dut, "show ip ospf vrf all database router", type='vtysh')
    st.show(dut, "show ip ospf vrf all database self-originate", type='vtysh')
    st.show(dut, "show ip ospf vrf all database max-age", type='vtysh')
    st.show(dut, "show ip ospf vrf all database asbr-summary", type='vtysh')
    return True


def rest_command_output_parsing(dut, vrf, type, cli_type='', filter_type='ALL'):
    """
    Author: Lakshminarayana D(lakshminarayana.d@broadcom.com)
    :param dut:
    :type vrf:
    :param type: neighbor, statistics, interface
    :return:
    """
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    vrf = 'default' if vrf == '' or vrf == 'default' else vrf
    if cli_type in get_supported_ui_type_list():
        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        ospf_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
        result = ospf_obj.get_payload(dut, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            st.log("test_step_failed: Failed to fetch the protocol information")
            return []
        if not result: return []
        ret_val = result.payload.get("openconfig-network-instance:protocol", '')
        if not ret_val:
            st.log("test_step_failed: Failed to fetch the ospf information")
            return []
        area_list = ret_val[0]['ospfv2']['areas']
    else:
        rest_urls = st.get_datastore(dut, "rest_urls")
        get_areas_uri = rest_urls['get_ospfv2_areas'].format(vrf)
        result = get_rest(dut, rest_url=get_areas_uri)
        if not result: return []
        area_list = result['output'].get('openconfig-network-instance:areas', '')
    if not area_list:
        st.warn("Couldn't found area list")
        return []
    area_identifiers = list(set([val['identifier'] for val in area_list['area']]))
    st.log('Area Idendifiers: {}'.format(area_identifiers))
    nbr_entries = []
    for area in area_identifiers:
        for url, intf_key, intf_subkey in zip(['get_ospfv2_areas_interfaces', 'get_ospfv2_areas_virual_links'], ['interfaces', 'virtual-links'], ['interface', 'virtual-link']):
            if cli_type in get_supported_ui_type_list():
                for area_info in area_list['area']:
                    if area_info['identifier'] == area:
                        interface_info = area_info.get(intf_key)
                        break
            else:
                get_areas_interfaces = rest_urls[url].format(vrf, area)
                result_intf = get_rest(dut, rest_url=get_areas_interfaces)
                if not result_intf:
                    st.error('Get Response Failed')
                    continue
                interface_info = result_intf['output'].get("openconfig-network-instance:{}".format(intf_key), '')
            if not interface_info:
                st.warn("Couldn't found interface list")
                continue
            for intf_list in interface_info[intf_subkey]:
                vir_link = False if intf_subkey != 'virtual-link' else True
                if type == 'neighbor':
                    neighbor_list = intf_list.get("openconfig-ospfv2-ext:neighbours", '')
                    if not neighbor_list: continue
                    neighbor_entry = neighbor_list.get('neighbour')
                    for entry in neighbor_entry:
                        temp = {}
                        ospf_states = {'LOADING': 'Loading', 'INIT': 'Init', 'FULL': 'Full', 'EXSTART': 'ExStart',
                                  'EXCHANGE': 'ExChange', 'Waiting': 'Waiting', 'TWO_WAY': '2-Way'}
                        temp['neighbhorid'] = entry['neighbor-id']
                        temp['priority'] = str(entry['state']['priority'])
                        state = entry['state']['adjacency-state'].split(':')[-1]
                        temp['state'] = ospf_states.get(state, '')
                        temp['deadtime'] = str(float(entry['state']['dead-time']) / 1000) + 's'
                        temp['neighboraddr'] = entry['neighbor-address']
                        temp['ifname'] = entry['state']['interface-name']
                        temp['ifip'] = entry['state']['interface-address']
                        temp['rxmtl'] = str(entry['state']['retransmit-summary-queue-length'])
                        temp['rqstl'] = str(entry['state']['link-state-request-queue-length'])
                        temp['dbsml'] = str(entry['state']['database-summary-queue-length'])
                        if temp['ifip'] == entry['state']['designated-router']:
                            temp['role'] = 'DR'
                        else:
                            temp['role'] = 'Backup'
                        temp['vrfname'] = '' if vrf == 'default' else vrf
                        temp['area_id'] = area
                        temp['vir_link'] = vir_link
                        temp['rem_router_id'] = '' if not vir_link else intf_list.get('remote-router-id')
                        nbr_entries.append(temp)
                elif type == 'interface':
                    temp = {}
                    state_info = intf_list.get('state','')
                    timer_info = intf_list.get('timers').get('state', '')
                    if intf_subkey == 'virtual-link':
                        state_info = intf_list.get('state','')
                        timer_info = intf_list.get('state','')
                    if not state_info and not timer_info:
                        st.warn("Couldn't found interface state or timer info")
                        continue
                    state_list = {'state': 'operational-state', 'index': 'index', 'mtu': 'mtu',
                                  'bw': 'bandwidth', 'linestate': 'if-flags', 'nwtype': 'ospf-interface-type',
                                  'area': 'area-id', 'rtrid': 'router-id',
                                  'bdr': 'backup-designated-router-id', 'bdrifip': 'backup-designated-router-address',
                                  'nbrstate': 'adjacency-status', 'priority': 'priority', 'txdelay': 'transmit-delay',
                                  'lsaseq': 'network-lsa-sequence-number', 'mcastmem': 'member-of-ospf-all-routers',
                                  'nbrcnt': 'neighbor-count', 'adjcnt': 'adjacency-count', 'cost': 'cost',
                                  'subnet': 'address-len', 'hellotmr': 'hello-interval', 'deadtmr': 'dead-interval',
                                  'waittmr': 'wait-time', 'rtxttmr': 'retransmission-interval', 'hellodue': 'hello-due'}

                    for item in [state_info, timer_info]:
                        for entry in item.keys():
                            for key, val in state_list.items():
                                if val in entry:
                                    temp[key] = str(item[entry])

                    temp['vrfname'] = vrf
                    temp['name'] = state_info['id']
                    temp['ipv4'] = state_info['openconfig-ospfv2-ext:address'] + '/' + str(state_info['openconfig-ospfv2-ext:address-len'])
                    temp['hellotmr'] = str(int(float(temp['hellotmr'])/1000))
                    temp['hellodue'] = str(float(temp.get('hellodue', 0))/1000)
                    temp['nwtype'] = temp['nwtype'].upper()
                    temp['txdelay'] = str(temp['txdelay'])
                    temp['mtumissmatch'] = 'enabled' if state_info.get('openconfig-ospfv2-ext:mtu-ignore', 'false') == 'false' else 'disabled'
                    temp['passive'] = 'Passive' if state_info.get('passive', '') == 'true' else ''
                    temp['area_id'] = area
                    temp['vir_link'] = vir_link
                    temp['rem_router_id'] = '' if not vir_link else intf_list.get('remote-router-id')
                    nbr_entries.append(temp)
                elif type == 'statistics':
                    temp = {}
                    stats_info = intf_list.get("openconfig-ospfv2-ext:message-statistics", '')
                    if not stats_info:
                        st.warn("Couldn't found interface statistics info")
                        continue
                    stats_info = intf_list["openconfig-ospfv2-ext:message-statistics"].get('state', '')
                    if not stats_info:
                        st.warn("Couldn't found interface statistics state info")
                        continue
                    temp['vrfname'] = vrf
                    temp['interface'] = intf_list['id']
                    temp['hello_rx'] = stats_info['hello-receive']
                    temp['hello_tx'] = stats_info['hello-transmit']
                    temp['dbd_rx'] = stats_info['db-description-receive']
                    temp['dbd_tx'] = stats_info['db-description-transmit']
                    temp['lsr_rx'] = stats_info['ls-request-receive']
                    temp['lsr_tx'] = stats_info['ls-request-transmit']
                    temp['lsu_rx'] = stats_info['ls-update-receive']
                    temp['lsu_tx'] = stats_info['ls-update-transmit']
                    temp['lsa_rx'] = stats_info['ls-acknowledge-receive']
                    temp['lsa_tx'] = stats_info['ls-acknowledge-transmit']
                    temp['area_id'] = area
                    temp['vir_link'] = vir_link
                    temp['rem_router_id'] = '' if not vir_link else intf_list.get('remote-router-id')
                    nbr_entries.append(temp)
    st.banner('OSPF - REST {} output'.format(type))
    st.log("OSPF - REST {} output is {}".format(type, nbr_entries))
    return nbr_entries


def verify_ospf_router_info(dut, vrf='', match={}, cli_type='', filter_type='ALL'):

    st.log("OSPF - Verify ospf router info on {} {}.".format(dut, vrf))

    result = True

    if vrf == '':
        vrf = 'default'

    if 'vrf' not in match.keys():
        match['vrfname'] = vrf

    rtr_entries = []
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if cli_type in get_supported_ui_type_list():
        max_metric_params = {'mmadtmr': 'mmadtype', 'mmsttype': 'mmsttmr', 'mmshtype': 'mmshtmr'}
        for type, timer in max_metric_params.items():
            if type in match and timer not in match:
                st.error('Mandatory param {} is not found in arguments to verify the param {}'.format(type, timer))
                return False
        match.pop('vrfname', '')
        attr_list = {
            'routerid': ['Ospfv2RouterId', match['routerid'] if 'routerid' in match else None],
            'writemultiplier': ['WriteMultiplier', match['writemultiplier'] if 'writemultiplier' in match else None],
            'rfc1583': ['OspfRfc1583Compatible', str(match['rfc1583']) if 'rfc1583' in match else None],
            'adjlogged': ['LogAdjacencyStateChanges', str(match['adjlogged']) if 'adjlogged' in match else None],
            'spfminhold': ['InitialDelay', int(match['spfminhold']) if 'spfminhold' in match else None],
            'spfmaxhold': ['MaximumDelay', int(match['spfmaxhold']) if 'spfmaxhold' in match else None],
            'spftmrstate': ['SpfTimerType', str(match['spftmrstate']) if 'spftmrstate' in match else None],
            'spfdelay': ['ThrottleDelay', int(match['spfdelay']) if 'spfdelay' in match else None],
            'refreshtimer': ['RefreshTimer', int(match['refreshtimer']) if 'refreshtimer' in match else None],
            'mmsttmr': ['OnStartup', int(match['mmsttmr']) if 'mmsttmr' in match else None],
            'opaqcapability': ['OpaqueLsaCapability', True if str(match.get('opaqcapability', '')).lower() == 'enabled' else False if 'opaqcapability' in match else None],
            'areacount': ['AreaCount', int(match['areacount']) if 'areacount' in match else None],
            'spfholdmultiplier': ['HoldTimeMultiplier', int(match['spfholdmultiplier']) if 'spfholdmultiplier' in match else None],
            'spflastexec': ['LastSpfExecutionTime', str(match['spflastexec']) if 'spflastexec' in match else None],
            'spflastduration': ['LastSpfDuration', int(match['spflastduration']) if 'spflastduration' in match else None],
            'extlsacount': ['ExternalLsaCount', int(match['extlsacount']) if 'extlsacount' in match else None],
            'extlsachksum': ['ExternalLsaChecksum', str(match['extlsachksum']) if 'extlsachksum' in match else None],
            'opqlsacount': ['OpaqueLsaCount', int(match['opqlsacount']) if 'opqlsacount' in match else None],
            'opqlsachksum': ['OpaqueLsaChecksum', str(match['opqlsachksum']) if 'opqlsachksum' in match else None],
            'lsamininterval': ['LsaMinIntervalTimer', int(match['lsamininterval']) if 'lsamininterval' in match else None],
            'lsaminarrival': ['LsaMinArrivalTimer', int(match['lsaminarrival']) if 'lsaminarrival' in match else None],
            'mmadtype': ['MaxMetricAdministrative', True if str(match.get('mmadtype', '')).lower() == 'admin' else None if 'mmadtype' in match else None],
            'mmadtmr': ['MaxMetricAdministrative', True if 'mmadtmr' in match else None],
            'mmsttype': ['OnStartup', int(match['mmsttmr']) if 'mmsttype' in match else None],
            'mmshtmr': ['OnStartup', int(match['mmshtmr']) if 'mmshtmr' in match else None],
            'mmshtype': ['OnStartup', int(match['mmshtmr']) if 'mmshtype' in match else None],
        }

        query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
        ni_obj = umf_ni.NetworkInstance(Name=vrf)
        ospf_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)

        for key in match.keys():
            if key in attr_list:
                if attr_list[key][1] is not None:
                    setattr(ospf_obj, attr_list[key][0], attr_list[key][1])
            else:
                st.error("Kindly add Argument {} to this variable \"attr_list\" in API \"verify_ospf_router_info\"".format(key))
                return False

        result = ospf_obj.verify(dut, match_subset=True, query_param=query_param_obj, cli_type=cli_type)
        if not result.ok():
            st.log("Match NOT found for params, kindly check actual and expected fields above")
            return False
        else:
            st.log("Match found for params provided")
        return result
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = "show ip ospf vrf {}".format(vrf)
        # cmd_str = "show ip ospf vrf all"
        # if get_ospf_cli_type(dut, cli_type=cli_type) == 'klish' : st.show(dut, cmd_str, type='vtysh')
        rtr_entries = st.show(dut, cmd_str, max_time=500, type=cli_type)
        st.log("OSPF - {} => Router output is {}".format(cmd_str, rtr_entries))
    elif cli_type in ["rest-patch", "rest-put"]:
        # var = {'template_key': 'ocyang-ext'}
        global_state_input_data = {'adjlogged': 'log-adjacency-state-changes', 'opqlsachksum': 'opaque-lsa-checksum',
                                   'opqlsacount': 'opaque-lsa-count', 'spflastexec': 'last-spf-execution-time',
                                   'opaqcapability': 'opaque-lsa-capability', 'rfc1583': 'ospf-rfc1583-compatible',
                                   'extlsachksum': 'external-lsa-checksum', 'routerid': 'router-id',
                                   'writemultiplier': 'write-multiplier',
                                   'extlsacount': 'external-lsa-count', 'areacount': 'area-count',
                                   'spfholdmultipler': 'hold-time-multiplier',
                                   'spflastduration': 'last-spf-duration'}

        global_timers_input_data = {'mmsttmr': 'on-startup', 'refreshtimer': 'refresh-timer',
                                    'spfminhold': 'initial-delay', 'spfdelay': 'throttle-delay',
                                    'spfmaxhold': 'maximum-delay', 'lsaminarrival': 'lsa-min-arrival-timer',
                                    'lsamininterval': 'lsa-min-interval-timer', 'spftmrstate': 'timer-type'}

        vrf = 'default' if vrf == '' else vrf
        rest_urls = st.get_datastore(dut, "rest_urls")

        global_state = 'get_ospfv2_global_state_{}'
        global_timers = 'get_ospfv2_global_timers_{}'

        parsed_output = {}

        for key, uri_ext in global_state_input_data.items():
            rest_id = global_state.format(key)
            url = rest_urls[rest_id].format(vrf)
            result = get_rest(dut, rest_url=url)
            if key == 'routerid':
                uri_ext = "openconfig-network-instance:{}".format(uri_ext)
            else:
                uri_ext = "openconfig-ospfv2-ext:{}".format(uri_ext)
            res_data = result['output'].get(uri_ext, '')
            parsed_output[key] = res_data

        for key, uri_ext in global_timers_input_data.items():
            rest_id = global_timers.format(key)
            url = rest_urls[rest_id].format(vrf)
            result = get_rest(dut, rest_url=url)
            if key in ['spfminhold', 'spfmaxhold', 'spftmrstate']:
                uri_ext = "openconfig-network-instance:{}".format(uri_ext)
            else:
                uri_ext = "openconfig-ospfv2-ext:{}".format(uri_ext)
            res_data = result['output'].get(uri_ext, '')
            parsed_output[key] = res_data

        vrf = 'default' if vrf == '' else vrf
        parsed_output['rfc'] = 'RFC2328'
        parsed_output['vrfname'] = vrf
        parsed_output['tos'] = 'TOS'
        parsed_output['toslist'] = 'TOS0'
        parsed_output['spfdelay'] = 0
        parsed_output['mmshtype'] = ''
        parsed_output['mmsthtmr'] = ''
        if parsed_output.get('rfc1583') == 'true':
            parsed_output['rfc1583'] = 'enabled'
        else:
            parsed_output['rfc1583'] = 'disabled'
        parsed_output['mmsttype'] = 'on-startup' if parsed_output.get('mmsthtmr') != 0 else ''
        if parsed_output:
            rtr_entries = [parsed_output]
            st.log("OSPF Router rest parsed output is {}".format(rtr_entries))
    else:
        st.error('Provided invalid UI-Type: {}'.format(cli_type))
        return False

    if not len(rtr_entries):
        st.log("OSPF - Zero ospf router records for vrf {}".format(vrf))
        result = False
    else:
        st.log("OSPF - match entries {} in router entries".format(match))

        rtr_records = filter_and_select(rtr_entries, None, {u'vrfname': vrf})
        if not len(rtr_records):
            st.log("OSPF - Router record not found for vrf {}".format(vrf))
            result = False
        else:
            st.log("OSPF - Router records matching vrf {} are {}".format(vrf, rtr_records))
            for rtr_record in rtr_records:
                match_found = True
                for match_key, match_value in match.items():
                    if match_key in rtr_record:
                        if rtr_record[match_key] != match_value:
                            st.log("OSPF - Router match value {} doesnt match".format(match_value))
                            match_found = False
                    else:
                        st.log("OSPF - Router match key {} not present".format(match_key))
                        match_found = False

                    if not match_found:
                        st.log("OSPF - Router didnot match {}:{}".format(match_key , match_value))
                        result = False

    result_str = "Success" if result else "Failed"
    st.log("OSPF - Router info {} check {}".format(match, result_str))
    return result


def verify_ospf_neighbor_state(dut, ospf_links, states, vrf='default', match={}, addr_family='ipv4', cli_type='', **kwargs):

    st.log("OSPF - Verify ospf neighbors on {} {}.".format(dut, vrf))

    result = True

    if not isinstance(ospf_links, list):
        ospf_links = [ ospf_links ]

    if not isinstance(states, list):
        states = [ states ]

    if vrf == '':
        vrf = 'default'

    area = kwargs.get('area')
    vir_link = kwargs.get('vir_link') or [False] * len(ospf_links)
    neigh_id = kwargs.get('neigh_id')
    neigh_addr = kwargs.get('neigh_addr')
    rem_router_id = kwargs.get('rem_router_id') or [''] * len(ospf_links)
    filter_type = kwargs.pop('filter_type', 'ALL')

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if cli_type in get_supported_ui_type_list():
        if not neigh_addr or not neigh_id or not area or not vir_link:
            nbr_entries = rest_command_output_parsing(dut, vrf, 'neighbor', filter_type=filter_type)
            if not len(nbr_entries):
                st.log("test_step_failed: OSPF - Zero neighbor records in vrf {}".format(vrf))
                return False
            area, neigh_id, neigh_addr, vir_link, rem_router_id = [list() for _ in range(5)]
            for intf in ospf_links:
                link_entries = filter_and_select(nbr_entries, None, {u'ifname': intf})
                st.banner("DUT{}: OSPF - NEIGHBORS for link:{} count:{}".format(dut,intf,len(link_entries)))
                if len(link_entries):
                    area.append(link_entries[0].get('area_id'))
                    neigh_id.append(link_entries[0].get('neighbhorid'))
                    neigh_addr.append(link_entries[0].get('neighboraddr'))
                    vir_link.append(link_entries[0].get('vir_link'))
                    rem_router_id.append(link_entries[0].get('rem_router_id'))
        for ele in [area, neigh_id, neigh_addr, vir_link, rem_router_id]:
            if len(make_list(ele)) != len(ospf_links):
                st.error('test_step_failed: Mandatory argument {} values are not proper'.format(ele))
                return False

        ospf_states = {'Loading': 'LOADING', 'Init': 'INIT', 'Full': 'FULL', 'ExStart': 'EXSTART',
                       'ExChange': 'EXCHANGE', 'Waiting': 'WAITING', '2-Way': 'TWO_WAY'}
        for index, intf in enumerate(ospf_links):
            nbr_attr_list = {
                'ifname': ['InterfaceName', intf],
                'ifip': ['InterfaceAddress', match['ifip'] if 'ifip' in match else None],
                'rxmtl': ['RetranmissionQueueLength', int(match['rxmtl']) if 'rxmtl' in match else None],
                'dbsml': ['DatabaseSummaryQueueLength', int(match['dbsml']) if 'dbsml' in match else None],
                'rqstl': ['LinkStateRequestQueueLength', int(match['rqstl']) if 'rqstl' in match else None],
                'deadtime': ['DeadTime', int(float(match['deadtime'].strip('s')) * 1000) if 'deadtime' in match else None],
                'priority': ['Priority', str(match['priority']) if 'priority' in match else None],
                'state': ['AdjacencyState', ospf_states[states[0]]],
                # 'role': [''],
            }

            query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
            ni_obj = umf_ni.NetworkInstance(Name=vrf)
            ospf_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
            area_obj = umf_ni.Area(Identifier=area[index], Protocol=ospf_obj)
            if not vir_link[index]:
                area_intf_obj = umf_ni.AreaInterface(InterfaceId=intf, Area=area_obj)
                nbr_obj = umf_ni.InterfaceNeighbour(NeighborId=neigh_id[index], NeighborAddress=neigh_addr[index],
                                                    AreaInterface=area_intf_obj)
            else:
                area_intf_obj = umf_ni.VirtualLink(RemoteRouterId=rem_router_id[index], Area=area_obj)
                nbr_obj = umf_ni.VirtualLinkNeighbour(NeighborId=neigh_id[index], NeighborAddress=neigh_addr[index],
                                                      VirtualLink=area_intf_obj)
            for key in list(match.keys()) + ['ifname', 'state']:
                if key not in ['area', 'neigh_id', 'neigh_addr', 'vir_link', 'rem_router_id']:
                    if key in nbr_attr_list:
                        if nbr_attr_list[key][1] is not None:
                            setattr(nbr_obj, nbr_attr_list[key][0], nbr_attr_list[key][1])
                    else:
                        st.error("Kindly add Argument {} to this variable \"nbr_attr_list\" "
                                 "in API \"verify_ospf_neighbor_state\"".format(key))
                        return False

            result = nbr_obj.verify(dut, match_subset=True, target_path='state', query_param=query_param_obj, cli_type=cli_type)
            if not result.ok():
                st.log("Match NOT found for neighbor {}; kindly check actual and expected fields above".format(intf))
                return False
            else:
                st.log("Match found for neighbor {}".format(intf))
        return result
    elif cli_type in ['vtysh', 'klish']:
        if cli_type == 'vtysh':
            ospf_links =  [get_intf_short_name(i) for i in ospf_links]
        cmd_str = "show ip ospf vrf {} neighbor".format(vrf)
        # cmd_str = "show ip ospf vrf default neighbor"

        # if get_ospf_cli_type(dut, cli_type=cli_type) == 'klish' : st.show(dut, cmd_str, type='vtysh')
        nbr_entries = st.show(dut, cmd_str, max_time=500, type=cli_type)
        st.log("OSPF - {} => Nbr output is {}".format(cmd_str, nbr_entries))
    elif cli_type in ["rest-patch", "rest-put"]:
        nbr_entries = rest_command_output_parsing(dut, vrf, 'neighbor')
    else:
        st.error('Provided invalid UI-Type: {}'.format(cli_type))
        return False

    if not len(nbr_entries):
        st.log("OSPF - Zero neighbor records in vrf {}".format(vrf))
        result = False
    else:
        for link_name in ospf_links:
            link_entries = filter_and_select(nbr_entries, None, {u'ifname':link_name})
            # st.log("OSPF - Link name {} matched entry {}".format(link_entries, link_entries))

            if not len(link_entries):
                st.log("OSPF - Neighbor record not found for {}".format(link_name))
                if '' in states:
                    return  True
                result = False
                break

            for nbr_record in link_entries:
                #st.log("OSPF - Nbr {}".format(nbr_record))
                if u'state' not in nbr_record.keys():
                    st.log("OSPF - State key not in link record")
                    result = False
                else:
                    if nbr_record[u'state'] not in states:
                        st.log("OSPF - State {} is not in state value {}".format(states, nbr_record[u'state']))
                        result = False
                    else:
                        # states match now match other fields
                        if not match_record_fields(nbr_record, match):
                            result = False

    result_str = "Success" if result else "Failed"
    st.log("OSPF - neighbor state {} check {}".format(states, result_str))
    return result


def verify_ospf_interface_info(dut, ospf_links, match={}, vrf='default', cli_type='', **kwargs):

    st.log("OSPF - Verify ospf neighbors on {} {}.".format(dut, vrf))

    result = True

    if not isinstance(ospf_links, list):
        ospf_links = [ ospf_links ]

    if vrf == '':
        vrf = 'default'

    if 'vrf' not in match.keys():
        match[u'vrfname'] = vrf

    area = kwargs.get('area')
    vir_link = kwargs.get('vir_link') or [False] * len(ospf_links)
    rem_router_id = kwargs.get('rem_router_id') or [''] * len(ospf_links)
    filter_type = kwargs.pop('filter_type', 'ALL')

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    # cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type in get_supported_ui_type_list():
        match.pop('vrfname', '')
        if not area or not vir_link:
            nbr_entries = rest_command_output_parsing(dut, vrf, 'interface', filter_type=filter_type)
            if not len(nbr_entries):
                st.log("test_step_failed: OSPF - Zero neighbor records in vrf {}".format(vrf))
                return False
            area, vir_link, rem_router_id = [list() for _ in range(3)]
            for intf in ospf_links:
                link_entries = filter_and_select(nbr_entries, None, {u'name': intf})
                st.log('link_entries for interface {}: {}'.format(intf, link_entries))
                if len(link_entries):
                    area.append(link_entries[0].get('area_id'))
                    vir_link.append(link_entries[0].get('vir_link'))
                    rem_router_id.append(link_entries[0].get('rem_router_id'))
        st.log("area: {}, vir_link: {}, rem_router_id {}".format(area, vir_link, rem_router_id))
        for ele in [area, vir_link, rem_router_id]:
            if len(make_list(ele)) != len(ospf_links):
                st.error('test_step_failed: Mandatory argument {} values are not proper'.format(ele))
                return False

        for index, intf in enumerate(ospf_links):
            nbr_attr_list = {
                'nwtype': ['OspfInterfaceType', match['nwtype'] if 'nwtype' in match else None],
                'priority': ['Priority', int(match['priority']) if 'priority' in match else None],
                'passive': ['Passive', True if str(match.get('passive')) else False if 'passive' in match else None],
                'area': ['AreaId', str(match['area']) if 'area' in match else None],
                'ipv4': ['Address', str(match['ipv4']).split('/')[0] if 'ipv4' in match else None],
                'subnet': ['AddressLen', str(match['subnet']) if 'subnet' in match else None],
                'mtumissmatch': ['MtuIgnore', True if str(match.get('mtumissmatch', '')).lower() == 'enabled' else False if 'mtumissmatch' in match else None],
                'index': ['Index', int(match['index']) if 'index' in match else None],
                'bw': ['Bandwidth', int(match['bw']) if 'bw' in match else None],
                'state': ['OperationalState', int(match['state']) if 'state' in match else None],
                'linestate': ['IfFlags', str(match['linestate']) if 'linestate' in match else None],
                'mtu': ['Mtu', int(match['mtu']) if 'mtu' in match else None],
                'rtrid': ['RouterId', str(match['rtrid']) if 'rtrid' in match else None],
                'nbrstate': ['AdjacencyStatus', str(match['nbrstate']) if 'nbrstate' in match else None],
                'dr': ['DesignatedRouter', str(match['dr']) if 'dr' in match else None],
                'bdr': ['BackupDesignatedRouterId', str(match['bdr']) if 'bdr' in match else None],
                'bdrifip': ['BackupDesignatedRouterAddress', str(match['bdrifip']) if 'bdrifip' in match else None],
                'other': ['DesignatedRouterOther', str(match['other']) if 'other' in match else None],
                'mcastmem': ['MemberOfOspfAllRouters', str(match['mcastmem']) if 'mcastmem' in match else None],
                'nbrcnt': ['NeighborCount', int(match['nbrcnt']) if 'nbrcnt' in match else None],
                'adjcnt': ['AdjacencyCount', int(match['adjcnt']) if 'adjcnt' in match else None],
                'cost': ['Cost', int(match['cost']) if 'cost' in match else None],
                'txdelay': ['InterfaceTransmitDelay', int(match['txdelay']) if 'txdelay' in match else None],
                'lsaseq': ['NetworkLsaSequenceNumber', str(match['lsaseq']) if 'lsaseq' in match else None],
                'deadtmr': ['DeadInterval', int(match['deadtmr']) if 'deadtmr' in match else None],
                'hellotmr': ['HelloInterval', int(match['hellotmr']) * 1000 if 'hellotmr' in match else None],
                'rtxttmr': ['RetransmissionInterval', int(match['rtxttmr']) if 'rtxttmr' in match else None],
                'waittmr': ['WaitTime', int(match['waittmr']) if 'waittmr' in match else None],
                'hellodue': ['HelloDue', int(match['hellodue']) * 1000 if 'hellodue' in match else None],
                'name': ['StateId', str(match['StateId']) if 'StateId' in match else None],
            }

            query_param_obj = get_query_params(yang_data_type=filter_type, cli_type=cli_type)
            ni_obj = umf_ni.NetworkInstance(Name=vrf)
            ospf_obj = umf_ni.Protocol(ProtoIdentifier='OSPF', Name='ospfv2', NetworkInstance=ni_obj)
            area_obj = umf_ni.Area(Identifier=area[index], Protocol=ospf_obj)
            if not vir_link[index]:
                area_intf_obj = umf_ni.AreaInterface(InterfaceId=intf, Area=area_obj)
            else:
                area_intf_obj = umf_ni.VirtualLink(RemoteRouterId=rem_router_id[index], Area=area_obj)
            for key in match.keys():
                if key not in ['area', 'vir_link', 'rem_router_id']:
                    if key in nbr_attr_list:
                        if nbr_attr_list[key][1] is not None:
                            setattr(area_intf_obj, nbr_attr_list[key][0], nbr_attr_list[key][1])
                    else:
                        st.error("Kindly add Argument {} to this variable \"nbr_attr_list\" "
                                 "in API \"verify_ospf_interface_info\"".format(key))
                        return False
            result = area_intf_obj.verify(dut, match_subset=True, target_path='state', query_param=query_param_obj,
                                          cli_type=cli_type)
            if not result.ok():
                st.log("Match NOT found for neighbor {}; kindly check actual and expected fields above".format(intf))
                return False
            else:
                st.log("Match found for neighbor {}".format(intf))
        return result
    elif cli_type in ['vtysh', 'klish']:
        cmd_str = "show ip ospf vrf {} interface".format(vrf)
        # cmd_str = "show ip ospf vrf default interface"

        # if get_ospf_cli_type(dut, cli_type=cli_type) == 'klish' : st.show(dut, cmd_str, type='vtysh')
        if_entries = st.show(dut, cmd_str, max_time=500, type=cli_type)
        st.log("OSPF - {} => Interface output is {}".format(cmd_str, if_entries))
    elif cli_type in ["rest-patch", "rest-put"]:
        if_entries = rest_command_output_parsing(dut, vrf, 'interface')
    else:
        st.error('Provided invalid UI-Type: {}'.format(cli_type))
        return False

    if not len(if_entries):
        st.log("OSPF - Zero interace records in vrf {}".format(vrf))
        result = False
    else:
        st.log("OSPF - match entries {} in interface info".format(match))
        for link_name in ospf_links:
            link_entries = filter_and_select(if_entries, None, {u'name':link_name})
            #st.log("OSPF - Link name {} matched entry {}".format(link_entries, link_entries))

            if not len(link_entries):
                st.log("OSPF - Interface record not found for {}".format(link_name))
                result = False

            for link_record in link_entries:
                #st.log("OSPF - Interface {}".format(link_record))
                match_found = True
                for match_key, match_value in match.items():
                    if match_key in link_record.keys():
                        if link_record[match_key] != match_value:
                            #st.log("OSPF - Interface {} match value {} doesnt match".format(link_name, match_value))
                            match_found = False
                    else:
                        #st.log("OSPF - Interface {} match key {} not present".format(link_name, match_key))
                        match_found = False

                    if not match_found:
                        st.log("OSPF - Interface {} did not match {}:{}".format(
                                            link_name, match_key , match_value))
                        result = False

    result_str = "Success" if result else "Failed"
    st.log("OSPF - Interface data {} check {}".format(match, result_str))
    return result


def verify_ospf_database(dut, lsdb_type, key_name='', key_value_list=[], vrf='default', match={}, addr_family='ipv4', cli_type=''):

    st.log("OSPF - Verify ospf {} lsdbs on {} {}.".format(lsdb_type, dut, vrf))

    result = True
    vrf = 'default' if vrf == '' else vrf

    lsdb_type_list = { 'router'         : 'router-LSA',
                       'network'        : 'network-LSA',
                       'summary'        : 'summary-LSA',
                       'asbr-summary'   : 'summary-LSA',
                       'external'       : 'AS-external-LSA',
                       'max-age'        : 'max-age-LSA',
                       'self-originate' : 'self-originate-LSA' }

    if lsdb_type not in lsdb_type_list.keys():
        st.log("OSPF - Invalid lsdb_type parameter {}.".format(lsdb_type))
        return False

    #cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    cli_type='vtysh'
    #if 'vrf' not in match.keys():
    #    if vrf != 'all':
    #        match[u'vrfname'] = vrf

    if 'lstype' not in  match.keys():
        match[u'lstype'] = lsdb_type_list[lsdb_type]

    cmd_str = "show ip ospf vrf {} database {}".format(vrf, lsdb_type)
    # cmd_str = "show ip ospf vrf all database {} ".format(lsdb_type)

    lsdb_entries = st.show(dut, cmd_str, max_time=500, type=cli_type)
    st.log("OSPF - {} => LSDB output is {}".format(cmd_str, lsdb_entries))

    if not len(lsdb_entries):
        st.log("OSPF - Zero lsdb records in vrf {}".format(vrf))
        result = False

    elif key_name == ''  or  len(key_value_list) == 0:
        matched_entries = filter_and_select(lsdb_entries, None, match)
        if not len(matched_entries):
            result = False

    else:
        st.log("OSPF - match key {}:{} in lsdb info".format(key_name, key_value_list))
        for key_value in key_value_list:

            key_match = { key_name: key_value }
            key_matched_entries = filter_and_select(lsdb_entries, None, key_match)
            # st.log("OSPF - Key name {}:{} matched entry {}".format(key_name, key_value, key_matched_entries)

            if not len(key_matched_entries):
                st.log("OSPF - Lsdb record not found for key {} {}".format(key_name, key_value))
                result = False

            if len(match) == 0:
                st.log("OSPF - Nothing to match in found key record")
                break

            record_matched = False
            for lsdb_record in key_matched_entries:
                # lsdb_type match now match other fields
                if match_record_fields(lsdb_record, match):
                    record_matched = True
            if not record_matched:
                result = False
                break

    result_str = "Success" if result else "Failed"
    st.log("OSPF - Lsdb type {} check {}".format(lsdb_type, result_str))
    return result


def verify_ospf_lsdb_info(dut, lsdb_type, key_name='', key_value_list=[], match={},
                          vrf='default', addr_family='ipv4', retry_count=4):
    result = False
    for retry in range (0, retry_count + 1):
        if retry > 0:
            st.log("OSPF - {} Retrying ospf lsdb with retry count {}".format(dut, retry))
            # retry after 10 seconds
            st.wait(10)

        result = verify_ospf_database(dut, lsdb_type=lsdb_type, vrf=vrf, addr_family=addr_family,
                                      key_name=key_name, key_value_list=key_value_list, match=match)
        if result:
            break

    return result


def verify_ip_route_info(dut, prefixes=None, match={}, vrf='default', protocol='', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    if cli_type in ["rest-patch", "rest-put"]: cli_type = 'klish'
    st.log("OSPF - Verify ip route on {} vrf {} prefix {} match {}.".format(dut, vrf, prefixes, match))

    result = True
    #cli_type = 'vtysh'

    if not prefixes:
        prefixes = []
    elif not isinstance(prefixes, list):
        prefixes = [ prefixes ]

    # if 'vrf' not in match.keys():
    #     if vrf != 'all':
    #         match[u'vrf_name'] = vrf
    pmap = { 'bgp': 'B', 'ospf': 'O', 'kernel': 'K', 'static': 'S', 'connected' : 'C' }

    cmd_str = "show ip route"

    if vrf != 'default' and vrf != '' :
        cmd_str += " vrf {}".format(vrf)

    if get_ospf_cli_type(dut, cli_type=cli_type) != 'klish' :
        cmd_str += " {}".format(protocol)

    if get_ospf_cli_type(dut, cli_type=cli_type) == 'klish' : st.show(dut, cmd_str, type='vtysh')
    route_entries = st.show(dut, cmd_str, max_time=500, type=cli_type)
    st.log("OSPF - {} => IP route output is {}".format(cmd_str, route_entries))

    if not len(route_entries):
        st.log("OSPF - Zero Route records in vrf {}".format(vrf))
        result = False
    elif len(prefixes) == 0:
        st.log("OSPF - match entries {} without prefix in ip route info".format(match))
        matched_entries = filter_and_select(route_entries, None, match)
        if not len(matched_entries):
            result = False
    else:
        st.log("OSPF - match entries {} {} in ip route info".format(prefixes, match))
        for ip_prefix in prefixes:
            prefix_match = {u'ip_address':ip_prefix}
            if protocol in pmap.keys() :
               prefix_match.update({u'type': pmap[protocol]})

            prefix_entries = filter_and_select(route_entries, None, prefix_match)
            st.log("OSPF - Ip prefix {} matched entry {}".format(ip_prefix, prefix_entries))

            if not len(prefix_entries):
                st.log("OSPF - Ip prefix record not found for {}".format(ip_prefix))
                result = False

            for prefix_record in prefix_entries:
                # st.log("OSPF - Route record {}".format(prefix_record))
                if not match_record_fields(prefix_record, match):
                   result = False

    result_str = "Success" if result else "Failed"
    st.log("OSPF - IP route data {} check {}".format(match, result_str))
    return result


def verify_ospf_ip_route_info(dut, prefixes=None, match={}, vrf='default', retry_count=4):

    if 'type' not in match.keys():
        match[u'type'] = 'O'

    result = False
    for retry in range (0, retry_count + 1):
        if retry > 0:
            st.log("OSPF - {} Retrying ip route ospf with retry count {}".format(dut, retry))
            # retry after 10 seconds
            st.wait(10)

        result = verify_ip_route_info(dut, prefixes=prefixes, vrf=vrf, match=match, protocol='ospf')
        if result:
            break

    return result


def verify_no_ip_route_info(dut, prefixes=None, match={}, vrf='default', protocol='', cli_type=''):
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    if cli_type in ["rest-patch", "rest-put"]: cli_type = 'klish'
    st.log("OSPF - Verify no ip route on {} vrf {} prefix {} match {}.".format(dut, vrf, prefixes, match))
    result = True

    if not prefixes:
        prefixes = []
    elif not isinstance(prefixes, list):
        prefixes = [ prefixes ]

    pmap = {'bgp': 'B', 'ospf': 'O', 'kernel': 'K', 'static': 'S', 'connected' : 'C' }

    cmd_str = "show ip route"

    if vrf != 'default' and vrf != '' :
        cmd_str += " vrf {}".format(vrf)

    if get_ospf_cli_type(dut, cli_type=cli_type) != 'klish' :
        cmd_str += " {}".format(protocol)

    if get_ospf_cli_type(dut, cli_type=cli_type) == 'klish' : st.show(dut, cmd_str, type='vtysh')
    route_entries = st.show(dut, cmd_str, max_time=500, type=cli_type)
    st.log("OSPF - {} => IP route output is {}".format(cmd_str, route_entries))

    if len(route_entries):
        for ip_prefix in prefixes:
            prefix_match = {u'ip_address':ip_prefix}
            if protocol in pmap.keys() :
               prefix_match.update({u'type': pmap[protocol]})

            prefix_entries = filter_and_select(route_entries, None, prefix_match)
            if len(prefix_entries):
                st.log("OSPF - Ip prefix record found for {}".format(ip_prefix))
                result = False

    result_str = "Success" if result else "Failed"
    st.log("OSPF - No IP route data {} check {}".format(match, result_str))
    return result


def verify_no_ospf_ip_route_info(dut, prefixes=None, match={}, vrf='default', retry_count=4):

    if 'type' not in match.keys():
        match[u'type'] = 'O'

    result = False
    for retry in range (0, retry_count + 1):
        if retry > 0:
            st.log("OSPF - {} Retrying no ip route ospf with retry count {}".format(dut, retry))
            # retry after 10 seconds
            st.wait(10)

        result = verify_no_ip_route_info(dut, prefixes=prefixes, vrf=vrf, match=match, protocol='ospf')
        if result:
            break

    return result


def verify_ospf_route(dut, vrf='default', **kwargs):
    """
    This proc is used for the verification of an entry in the OSPF routing table
    :param :dut:
    :param :type:
    :param :selected:
    :param :fib:
    :param :ip_address:
    :param :interface:
    :param :duration:
    :param :nexthop:
    :param :distance:
    :param :cost:
    :param :vrf_name
    :return:
    """
    ret_val = False
    st.log("OSPF - Verify ospf routing table on DUT {} , vrf {}.".format(dut, vrf))

    if vrf == '':
        vrf = 'default'

    result = show_ospf_route(dut, vrf)
    for rlist in result:
        count = 0
        for key in kwargs:
            if rlist[key] == kwargs[key]:
                count = count + 1
        if len(kwargs) == count:
            ret_val = True
            for key in kwargs:
                st.log("Match: Match key {} found => {}: {}".format(key, kwargs[key], rlist[key]))
            break
        else:
            for key in kwargs:
                if rlist[key] == kwargs[key]:
                    st.log("Match: Match key {} found => {}: {}".format(key, kwargs[key], rlist[key]))
                else:
                    st.log("No-Match: Match key {} NOT found => {}: {}".format(key, kwargs[key], rlist[key]))
            st.log("\n")

    if not ret_val:
        st.log("Fail: Not Matched all args in passed dict {} from parsed dict".format(kwargs))
    return ret_val


def verify_route_summary(dut, exp_num_of_routes, vrf='default', key='ospf',neg_check='no',route_type='software'):

    if route_type == 'software':
        current_routes = fetch_ip_route_summary(dut, vrf=vrf, key=key)
    else:
        current_routes = asicapi.get_ipv4_route_count(dut)
    if neg_check != 'no':
        if int(current_routes) < exp_num_of_routes:
            st.log('PASS - Expected number of {} routes present in the {}'.format(key, route_type))
            return True
        st.log('FAIL - Expected number of {} routes not present in the {}'.format(key, route_type))
        return False
    if int(current_routes) >= exp_num_of_routes:
        st.log('PASS - Expected number of {} routes present in the {}'.format(key, route_type))
        return True

    st.log('FAIL - Expected number of {} routes not present in the {}'.format(key, route_type))
    return False


def show_ospf_route(dut, vrf='default', cli_type=''):
    """
    This proc used for displaying the OSPF routing table.
    :param dut:
    :param vrf:
    :return:
    """

    st.log("OSPF - Ospf routing table on DUT {} , vrf {}.".format(dut, vrf))

    if vrf == '':
        vrf = 'default'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)

    if cli_type in ["rest-patch", "rest-put"]+get_supported_ui_type_list(): cli_type = 'klish'

    cmd_str = "show ip route vrf {} ospf".format(vrf)
    output = st.show(dut, cmd_str, type=cli_type)
    return output


def fetch_ospf_interface_info(dut, ospf_link, key='cost', vrf='default', cli_type=''):
    """
    This proc is used to fetch the value of parameter mentioned as part of 'match' arg
    If the match found, the coorresponding value will returned. Otherwise, it will return false.
    :param dut:
    :param ospf_link:
    :param key:
    :param vrf:
    :return:
    """
    result = True
    if vrf == '':
        vrf = 'default'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type in ['vtysh', 'klish']:
        cmd_str = "show ip ospf vrf {} interface {}".format(vrf, ospf_link)
        if_entries = st.show(dut, cmd_str, type=cli_type)
    elif cli_type in ["rest-patch", "rest-put"]:
        if_entries = rest_command_output_parsing(dut, vrf, 'interface')
    else:
        st.error('Provided invalid UI-Type: {}'.format(cli_type))
        return False

    if not len(if_entries):
        st.log("OSPF - Zero interace records in vrf {}".format(vrf))
        result = False
    else:
        st.log("OSPF - match entries {} in interface info".format(key))
        link_entries = filter_and_select(if_entries, None, {u'name': ospf_link})

        if not len(link_entries):
          st.log("OSPF - Interface record not found for {}".format(ospf_link))
          result = False
        for link_record in link_entries:
          if key in link_record.keys():
            result=link_record[key]
            match_found = True
          else:
            match_found = False

          if not match_found:
            st.log("OSPF - Interface {} output did not match the key {}:".format(ospf_link, key))
            result = False
    return result


def get_ospf_interface_traffic(dut, ospf_links, key='', vrf='default', cli_type=''):
    st.log("OSPF - get ospf neighbors traffic info on {} {}.".format(dut, vrf))

    result = []

    if not isinstance(ospf_links, list):
        ospf_links = [ospf_links]

    if vrf == '':
        vrf = 'default'

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    cli_type = force_cli_type_to_klish(cli_type=cli_type)

    if cli_type in ['vtysh', 'klish']:
        cmd_str = "show ip ospf vrf {} interface traffic".format(vrf)

        if_entries = st.show(dut, cmd_str, type=get_ospf_cli_type(dut, cli_type=cli_type))
        st.log("OSPF - {} => Interface output is {}".format(cmd_str, if_entries))
    elif cli_type in ["rest-patch", "rest-put"]:
        if_entries = rest_command_output_parsing(dut, vrf, 'statistics')
    else:
        st.error('Provided invalid UI-Type: {}'.format(cli_type))
        return False

    if not len(if_entries):
        st.log("OSPF - Zero interace records in vrf {}".format(vrf))
        result = -1
    else:
        st.log("OSPF - match entries {} in interface info".format(key))
        for link_name in ospf_links:
            link_entries = filter_and_select(if_entries, None, {u'interface': link_name})

            if not len(link_entries):
                st.log("OSPF - Interface record not found for {}".format(link_name))
                result.append(-1)
            else:
                for link_record in link_entries:
                    if key in link_record.keys():
                        result.append(int(link_record[key]))
                    else:
                        st.log("OSPF - Interface {} did not match {}".format(link_name, key))
                        result = -1

    result_str = "Success" if result != -1 else "Failed"
    st.log("OSPF - Interface data {} check {}".format(key, result_str))
    return result


def fetch_ip_route_summary(dut, vrf='default', key = 'ospf',version='ip', cli_type=''):
    """
    :param dut:
    :param vrf:
    :param key:
    :param match:
    :return:
    """

    st.log("Routing table summary on DUT {} , vrf {}.".format(dut, vrf))

    if vrf == '':
        vrf = 'default'

    cmd_str = "show {} route vrf {} summary".format(version,vrf)

    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    if cli_type in ["rest-patch", "rest-put"]+get_supported_ui_type_list(): cli_type = 'klish'

    output = st.show(dut, cmd_str, type=cli_type)

    link_entries = filter_and_select(output, None, {u'vrf': vrf})
    st.log("OSPF - Routing table summary  {}".format(link_entries))
    result = ''
    for link_record in link_entries:
        if key in link_record.keys():
            result = link_record[key]
            break

    return result if result else 0


def get_ethtool_interface(dut, interface, key=''):
    st.log("ethtool info on interface {}, DUT {}".format(interface, dut))

    interface = convert_intf_name_to_component(dut, intf_list=interface)
    '''
    if '/' in interface:
        interface = st.get_other_names(dut,[interface])[0]
    '''

    cmd = "/sbin/ethtool " + interface
    output = st.show(dut, cmd)

    link_entries = filter_and_select(output, None, {u'interface': interface})

    if not link_entries:
        st.error("No output found - {}".format(output))
        return False

    if key == '':
        return output
    else:
        match_found = True
        result = ''
        for link_record in link_entries:
            if key in link_record.keys():
                result = link_record[key]
                match_found = True
                break
            else:
                match_found = False

    if (not match_found) or (result == ''):
        result = False

    return result


# ------------------ OSPF Config dispaly APIs -------------------------------------

def show_ospf_running_config(dut_list, cli_type='vtysh'):
    if not isinstance(dut_list, list):
        dut_list = [dut_list]
    for dut in dut_list :
        if cli_type == 'klish' :
            st.show(dut,"show running-configuration ospf", type='klish')
        else :
            st.show(dut,"show running-config ospfd", type='vtysh')
    return True, 'Success'

def match_config_record(config_record={}, config_match={}):

    if len(config_record) == 0 :
        st.log("OSPF - Router record empty")
        return False

    if len(config_match) == 0 :
        st.log("OSPF - match record empty - return match Success")
        return True

    if u'cfg_line' not in config_record.keys() :
        return False

    cfg_line = config_record[u'cfg_line']
    if cfg_line == '' :
        return False

    #st.log("OSPF - Config line - {}.".format(cfg_line))
    match_found = True
    matches_done = False

    for match_key, match_value in config_match.items() :
        if match_value != '' :
            match_str = "{} {}".format(match_key, match_value)
        else :
            match_str = "{}".format(match_key)
        #st.log("OSPF - match_str {}".format(match_str))

        matches_done = True
        if cfg_line.find(match_str) < 0 :
            match_found = False
            break

    if match_found and matches_done :
        st.log("OSPF - Config record line {} =>matched=> {}".format(cfg_line, config_match))
        return True

    #st.log("OSPF - config line {} => didnot match => {}".format(cfg_line, config_match))
    return False


def verify_ospf_router_config(dut, vrf='', match=None, cli_type=''):

    result = False
    st.log("OSPF - Verify ospf router config on {} {} matching {}.".format(dut, vrf, match))

    input_cli_type = cli_type
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    if cli_type in ["rest-patch", "rest-put"]: cli_type = 'klish'

    match_list = [ {} ] if match is None else match
    if not isinstance(match_list, list):
        match_list = [match]

    cli_type_map = {}
    if input_cli_type == 'klish' :
        cli_type_map.update( {'klish' : False} )
    elif input_cli_type == 'vtysh' :
        cli_type_map.update( { 'vtysh': False} )
    else :
        cli_type_map = { 'vtysh': False}
        if cli_type == 'klish' :
            cli_type_map.update( {'klish' : False} )

    for ctype in cli_type_map.keys() :
        if ctype == 'klish' :
            cmd_str = "show running-configuration ospf"
        else :
            cmd_str = "show running-config ospfd"

        config_entries = st.show(dut, cmd_str, type=ctype)
        st.log("OSPF - {} => {} Running config is {}".format(cmd_str, ctype, config_entries))
        st.log("")

        if not len(config_entries):
            st.log("OSPF - Zero ospf config records for vrf {}".format(vrf))
            result = False
        else:
            vrf_str = vrf
            if vrf == 'default' : vrf_str = ''
            rtr_match = {u'router_type': 'ospf', u'router_vrf': vrf_str }
            st.log("OSPF - match entries {} + {} in router entries".format(rtr_match, match))

            rtr_records = filter_and_select(config_entries, None, rtr_match)
            if not len(rtr_records):
                st.log("OSPF - Router record not found for vrf {}.".format(vrf))
                result = False
            else :
                match_count = 0
                for cfg_match in match_list :
                    if len(cfg_match) == 0 :
                        st.log("OSPF - Empty input match consider record with vrf {} as matched".format(vrf))
                        match_count += 1
                        continue

                    #st.log("OSPF - Router records matching vrf {} are {}".format(vrf, rtr_records))
                    match_result = False
                    for rtr_record in rtr_records:
                        match_result = match_config_record(config_record=rtr_record, config_match=cfg_match)
                        if match_result :
                            match_count += 1
                            break

                    if match_result is False :
                        st.log("OSPF - Router config didnot match {}".format(cfg_match))

                if match_count == len(match_list) :
                    result = True

        cli_type_map[ctype] = result
        if result is not True :
            break

    result_str = "Success" if result else "Failed"
    st.log("OSPF - Router config {} check {}".format(match, result_str))
    return result


def verify_no_ospf_router_config(dut, vrf='', match=None, cli_type=''):

    result = False
    match_list = [ {} ] if match is None else match
    if not isinstance(match_list, list):
        match_list = [match]

    match_count = 0
    for cfg_match in match_list :
        match_result = verify_ospf_router_config(dut, vrf=vrf, match=cfg_match, cli_type=cli_type)
        if match_result is False :
            st.log("OSPF - Router config {} not present".format(cfg_match))
            match_count += 1

    if match_count == len(match_list) :
        result = True

    result_str = "Success" if result else "Failed"
    st.log("OSPF - Router no config {} check {}".format(match, result_str))
    return result


def verify_ospf_interface_config(dut, interfaces, native_intfs, vrf='', match=None, cli_type=''):

    result = False
    st.log("OSPF - Verify ospf interface config on {} {} actual ifs {} matching {}.".format(dut, vrf, interfaces, match))
    st.log("OSPF - Verify ospf interface config on {} {} native ifs {} matching {}.".format(dut, vrf, native_intfs, match))

    input_cli_type = cli_type
    cli_type = get_ospf_cli_type(dut, cli_type=cli_type)
    if cli_type in ["rest-patch", "rest-put"]: cli_type = 'klish'

    if not isinstance(interfaces, list):
        interfaces = [interfaces]

    if not isinstance(native_intfs, list):
        native_intfs = [native_intfs]

    match_list = [ {} ] if match is None else match
    if not isinstance(match_list, list):
        match_list = [match]

    cli_type_map = {}
    if input_cli_type == 'klish' :
        cli_type_map.update( {'klish' : False} )
    elif input_cli_type == 'vtysh' :
        cli_type_map.update( { 'vtysh': False} )
    else :
        cli_type_map = { 'vtysh': False}
        if cli_type == 'klish' :
            cli_type_map.update( {'klish' : False} )

    for ctype in cli_type_map.keys() :
        if ctype == 'klish' :
            cmd_str = "show running-configuration ospf interface"
            interface_list = interfaces
        else :
            cmd_str = "show running-config ospfd"
            interface_list = native_intfs

        config_entries = st.show(dut, cmd_str, type=ctype)
        st.log("OSPF - {} => {} Running interface config is {}".format(cmd_str, ctype, config_entries))
        st.log("")

        if not len(config_entries):
            st.log("OSPF - Zero ospf config records for vrf {}".format(vrf))
            result = False
        else:
            vrf_str = '' if vrf == 'default' else vrf
            one_if_fail = False

            for interface in interface_list :
                intf_match = {u'interface': interface, u'interface_vrf': vrf_str }

                #st.log("OSPF - match entries {} + {} in interface entries".format(intf_match, match))

                intf_records = filter_and_select(config_entries, None, intf_match)
                if not len(intf_records):
                    st.log("OSPF - Interface record not found for vrf {}.".format(vrf))
                    result = False
                    one_if_fail = True
                else :
                    match_count = 0
                    for cfg_match in match_list :
                        if len(cfg_match) == 0 :
                            st.log("OSPF - Empty input match consider record with vrf {} as matched".format(vrf))
                            match_count += 1
                            continue

                        for intf_record in intf_records:
                            match_result = match_config_record(config_record=intf_record, config_match=cfg_match)
                            if match_result :
                                match_count += 1
                                break

                        if match_result is False :
                            st.log("OSPF - Interface {} config didnot match {}".format(interface, cfg_match))

                    if match_count != len(match_list) :
                        one_if_fail = True
                        break

                if one_if_fail :
                    result = False
                    break

            result = False if one_if_fail else True

        cli_type_map[ctype] = result
        if result is not True :
            break

    result_str = "Success" if result else "Failed"
    st.log("OSPF - Router config {} check {}".format(match, result_str))
    return result


def verify_no_ospf_interface_config(dut, interface, native_intfs, vrf='', match=None, cli_type=''):

    result = False
    match_list = [ {} ] if match is None else match
    if not isinstance(match_list, list):
        match_list = [match]

    match_count = 0
    for cfg_match in match_list :
        match_result = verify_ospf_interface_config(dut, interface, native_intfs, vrf=vrf, match=cfg_match, cli_type=cli_type)
        if match_result is False:
            st.log("OSPF - Interface config {} not present".format(cfg_match))
            match_count += 1

    if match_count == len(match_list) :
        result = True

    result_str = "Success" if result else "Failed"
    st.log("OSPF - Interface no config {} check {}".format(match, result_str))
    return result


# ------------------ OSPF conatiner or system restart APIs -------------------------------------

def ospf_container_start_stop(dut, action='start'):

    command = []

    if action not in [ 'start', 'stop' ]:
        st.log("OSPF - Invalid action parameter {}.".format(action))
        return False

    cmd_str = "sudo docker {} bgp".format(action)
    command.append(cmd_str)
    result = st.config(dut, command)
    result = validate_config_result(command, result, "docker:")

    command = []
    command.append("sleep 2")
    command.append('docker container ls --filter "name=bgp" ')
    st.config(dut, command)
    return result


def ospf_dut_or_container_restart(duts, rest_type='bgp', rest_sub_type='cold',
                                  save_frr_config='no', save_sonic_config='no', cli_type=''):

    st.log("OSPF - Restart dut {} rest_type {} rest_sub_type {} ".format(duts, rest_type, rest_sub_type))
    st.log("OSPF - save_frr_config {} save_sonic_config {}".format(save_frr_config, save_sonic_config))

    if not isinstance(duts, list):
        duts = [ duts ]

    if rest_type not in ['bgp', 'dut'] :
        st.log("OSPF - Invalid rest_type option{}.".format(rest_type))
        return False

    if rest_sub_type not in ['cold', 'warm', 'fast'] :
        st.log("OSPF - Invalid rest_sub_type option{}.".format(rest_sub_type))
        return False

    if save_frr_config not in ['yes', 'no'] :
        st.log("OSPF - Invalid save_frr_config option{}.".format(save_frr_config))
        return False

    if save_sonic_config not in ['yes', 'no'] :
        st.log("OSPF - Invalid save_sonic_config option{}.".format(save_sonic_config))
        return False

    restarted_duts = {}

    for dut in duts :

        routing_mode = 'separated'
        routing_mode_cfg = get_attr_from_cfgdbjson(dut, "docker_routing_config_mode")
        st.log("OSPF - {} json db routing mode config {}".format(dut, routing_mode_cfg))
        if routing_mode_cfg.find("docker_routing_config_mode") >= 0 :
            if routing_mode_cfg.find("split") >= 0 :
                routing_mode = 'split'
            elif routing_mode_cfg.find("unified") >= 0 :
                routing_mode = 'unified'
        st.log("OSPF - {} routing mode is {}".format(dut, routing_mode))

        st.log("OSPF - {} Current FRR running config ".format(dut))
        st.show(dut, "show running-config", type='vtysh')

        st.log("OSPF - {} Current FRR startup config ".format(dut))
        st.show(dut, "show startup-config", type='vtysh')

        st.log("OSPF - {} Current warm restart config ".format(dut))
        st.show(dut, "sudo show warm_restart config", type='click')

        if save_frr_config == 'yes' :
            if routing_mode == 'split' :
                st.log("OSPF - {} Saving FRR config".format(dut))
                config_save(dut, shell='vtysh')

                st.log("OSPF - {} FRR startup config after config save ".format(dut))
                st.show(dut, "show startup-config", type='vtysh')
                st.show(dut, "sudo docker exec -it bgp bash -c \"cat /etc/frr/*.conf\"", type='click')
            else :
                st.log("OSPF - {} Not saving FRR config since routing mode is {}".format(dut, routing_mode))

        if save_sonic_config == 'yes' :
            st.log("OSPF - {} Saving Sonic config DB".format(dut))
            config_save(dut, shell='sonic')

            st.log("OSPF - {} Sonic startup config after config save ".format(dut))
            st.show(dut, "sudo cat /etc/sonic/config_db.json", type='click')

        if rest_type in ['bgp'] :
            st.log("OSPF - {} Restarting BGP docker ".format(dut))
            service_operations_by_systemctl(dut, service='bgp', operation='restart')
        elif rest_type in ['dut'] :
            st.log("OSPF - {} {} Restarting DUT ".format(dut, rest_sub_type))
            if rest_sub_type in [ 'warm', 'fast' ] :
                st.reboot(dut, rest_sub_type)
            else :
                st.reboot(dut)

        restarted_duts.update({ dut : False})


    st.log("OSPF - Verifying restart status of {}.".format(restarted_duts.keys()))
    for retry in range (0, 12) :
        all_dut_up = True
        for res_dut in restarted_duts.keys() :
            if restarted_duts[res_dut] is False :
                all_dut_up = False
                break
        if all_dut_up :
            break

        if retry > 0 : st.wait(5)
        st.log("OSPF - Restart status check retry count {}.".format(retry))

        for dut in restarted_duts :
            if restarted_duts[dut] is False :
                result = False
                if rest_type in ['bgp'] :
                    result = get_system_status(dut, service='bgp')
                elif rest_type in ['dut'] :
                    result = get_system_status(dut)
                if result :
                    st.log("OSPF - {} {} Restarting status Success ".format(dut, rest_type))
                    restarted_duts[dut] = True

    st.log("OSPF - Restart status {}".format(restarted_duts))
    all_dut_restarted = True
    for dut in duts :
        st.log("OSPF - {} FRR startup config after restart ".format(dut))
        st.show(dut, "show startup-config", type='vtysh')
        st.config(dut, "sudo docker exec -it bgp bash -c \"cat /etc/frr/*.conf\"", type='click')

        st.log("OSPF - {} FRR running config after restart ".format(dut))
        st.show(dut, "show running-config", type='vtysh')

        if rest_type in ['dut'] and save_sonic_config == 'yes' :
            st.log("OSPF - {}  Sonic DB running config after restart".format(dut))
            st.show(dut, "sudo show runningconfiguration all", type='click')

        if dut not in restarted_duts.keys() :
           st.log("OSPF - {} BGP container Restarting failed ".format(dut))
           all_dut_restarted = False
           continue

        if restarted_duts[dut] is False :
           st.log("OSPF - {} BGP container didnot come up".format(dut))
           all_dut_restarted = False
           continue

        st.log("OSPF - {} BGP container come up successfuly".format(dut))

    if all_dut_restarted :
        st.log("OSPF - {} {} restart Success".format(duts, rest_type))
    else :
        st.log("OSPF - {} {} restart Failed".format(duts, rest_type))
    st.log("")
    return all_dut_restarted

# --------------------------------------------------------------------------
def config_ospf_gr_prepare(dut, **kwargs):
    cli_type = kwargs.get("cli_type", st.get_ui_type(dut))
    if cli_type in ['rest-patch', 'rest-put']: cli_type = 'klish'
    cli_type = force_cli_type_to_klish(cli_type=cli_type)
    st.config(dut,"graceful-restart prepare ip ospf", type=cli_type, conf=False, skip_error_check=True)
