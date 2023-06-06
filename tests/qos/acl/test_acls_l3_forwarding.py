import pprint
import pytest
import json
import re

from spytest import st, tgapi, SpyTestDict

import apis.qos.acl as acl_obj
import tests.qos.acl.acl_json_config as acl_data
import tests.qos.acl.acl_utils as acl_utils
import tests.qos.acl.acl_rules_data as acl_rules_data
import tests.qos.acl.acl_lib as acl_lib
import apis.switching.portchannel as pc_obj
import apis.routing.ip as ip_obj
import apis.routing.arp as arp_obj
import apis.system.basic as basic_obj
import utilities.common as utils
import utilities.utils as utils_obj
try:
    from apis.yang.utils.common import Operation
except ImportError:
    pass

pp = pprint.PrettyPrinter(indent=4)

vars = dict()
data = SpyTestDict()
data.rate_pps = 100
data.pkts_per_burst = 10
data.tx_timeout = 2
data.TBD = 10
data.portChannelName = "PortChannel111"
data.tg_type = 'ixia'
data.ipv4_address_D1 = "1.1.1.1"
data.ipv4_address_D2 = "2.2.2.1"
data.ipv4_portchannel_D1 = "192.168.1.1"
data.ipv4_portchannel_D2 = "192.168.1.2"
data.ipv4_network_D1 = "1.1.1.0/24"
data.ipv4_network_D2 = "2.2.2.0/24"
data.ipv6_address_D1 = "1001::1"
data.ipv6_address_D2 = "2001::1"
data.ipv6_portchannel_D1 = "3001::1"
data.ipv6_portchannel_D2 = "3001::2"
data.ipv6_network_D1 = "1001::0/64"
data.ipv6_network_D2 = "2001::0/64"
data.acl_type = "ipv6"

##### gnmi replace vars #####
data.create_ipacl = 'ipacl'
data.create_ipv6acl = 'ipv6acl'
data.typev4 = 'ip'
data.create_seq = 60
data.create_action = 'DROP'
data.create_sip = '10.0.0.1/24'
data.create_dip = '20.0.0.1/24'
data.create_proto = 'udp'
data.create_dscp = 8
data.create_sipv6 = '1300:01::01/64'
data.create_dipv6 = '1300:01::02/64'
data.default_ip = 'any'
data.repl_action = 'ACCEPT'
data.repl_sip = '12.12.1.1/24'
data.repl_dip = '1.1.1.1/24'
data.repl_proto = 'tcp'
data.repl_dscp = 0
data.repl_sipv6 = '1212:01::01/64'
data.repl_dipv6 = '1001::1/64'
data.src_mac = "00:0a:01:00:00:01"

def print_log(msg):
    utils.print_log(msg)


def get_handles():
    '''
    ######################## Topology ############################

               +---------+                  +-------+
               |         +------------------+       |
      TG1 -----|  DUT1   |  portchannel     |  DUT2 +----- TG2
               |         +------------------+       |
               +---------+                  +-------+

    ##############################################################
    '''
    global vars
    vars = st.ensure_min_topology("D1D2:2", "D1T1:1", "D2T1:1")
    tg1, tg_ph_1 = tgapi.get_handle_byname("T1D1P1")
    tg2, tg_ph_2 = tgapi.get_handle_byname("T1D2P1")
    if tg1.tg_type == 'stc': data.tg_type = 'stc'
    tg1.tg_traffic_control(action="reset", port_handle=tg_ph_1)
    tg2.tg_traffic_control(action="reset", port_handle=tg_ph_2)
    return (tg1, tg2, tg_ph_1, tg_ph_2)


def apply_module_configuration():
    print_log("Applying module configuration")

    data.dut1_lag_members = [vars.D1D2P1, vars.D1D2P2]
    data.dut2_lag_members = [vars.D2D1P1, vars.D2D1P2]

    # create portchannel
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.create_portchannel, vars.D1, data.portChannelName),
        utils.ExecAllFunc(pc_obj.create_portchannel, vars.D2, data.portChannelName),
    ])

    # add portchannel members
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.add_portchannel_member, vars.D1, data.portChannelName, data.dut1_lag_members),
        utils.ExecAllFunc(pc_obj.add_portchannel_member, vars.D2, data.portChannelName, data.dut2_lag_members),
    ])
    if data.intf_mode:
        data.portChannelName = data.portChannelName + "." + "1"
        utils.exec_all(True, [
            utils.ExecAllFunc(ip_obj.config_sub_interface, vars.D1, data.portChannelName, create_parent_po=True, vlan=10),
            utils.ExecAllFunc(ip_obj.config_sub_interface, vars.D2, data.portChannelName, create_parent_po=True, vlan=10),
        ])



def clear_module_configuration():
    print_log("Clearing module configuration")
    # delete Ipv4 address
    print_log("Delete ip address configuration:")
    ip_obj.clear_ip_configuration([vars.D1, vars.D2], family='ipv4')
    # delete Ipv6 address
    ip_obj.clear_ip_configuration([vars.D1, vars.D2], family='ipv6')
    # delete ipv4 static routes
    ip_obj.delete_static_route(vars.D1, data.ipv4_portchannel_D2, data.ipv4_network_D2, shell="vtysh",
                               family="ipv4")
    ip_obj.delete_static_route(vars.D2, data.ipv4_portchannel_D1, data.ipv4_network_D1, shell="vtysh",
                               family="ipv4")
    # delete ipv6 static routes
    ip_obj.delete_static_route(vars.D1, data.ipv6_portchannel_D2, data.ipv6_network_D2, shell="vtysh",
                               family="ipv6")
    ip_obj.delete_static_route(vars.D2, data.ipv6_portchannel_D1, data.ipv6_network_D1, shell="vtysh",
                               family="ipv6")
    # delete port channel members
    print_log("Deleting members from port channel:")
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.delete_portchannel_member, vars.D1, data.portChannelName, data.dut1_lag_members),
        utils.ExecAllFunc(pc_obj.delete_portchannel_member, vars.D2, data.portChannelName, data.dut2_lag_members),
    ])
    # delete port channel
    print_log("Deleting port channel configuration:")
    utils.exec_all(True, [
        utils.ExecAllFunc(pc_obj.delete_portchannel, vars.D1, data.portChannelName),
        utils.ExecAllFunc(pc_obj.delete_portchannel, vars.D2, data.portChannelName),
    ])
    # delete acl tables and rules
    print_log("Deleting ACLs:")

    utils.exec_all(True, [[acl_obj.acl_delete, vars.D1], [acl_obj.acl_delete, vars.D2]])
    #Clear static arp entries
    print_log("Clearing ARP entries")
    arp_obj.clear_arp_table(vars.D1)
    arp_obj.clear_arp_table(vars.D2)
    #Clear static ndp entries
    print_log("Clearing NDP entries")
    arp_obj.clear_ndp_table(vars.D1)
    arp_obj.clear_ndp_table(vars.D2)

def add_port_to_acl_table(config, table_name, port):
    config['ACL_TABLE'][table_name]['ports'].append(port)


def apply_acl_config(dut, config):
    json_config = json.dumps(config)
    json.loads(json_config)
    st.apply_json2(dut, json_config)


def create_streams(tx_tg, rx_tg, rules, match, mac_src, mac_dst, return_stream=False):
    # use the ACL rule definitions to create match/non-match traffic streams
    # instead of hard coding the traffic streams
    my_args = {
        'port_handle': data.tgmap[tx_tg]['handle'], 'mode': 'create', 'frame_size': '128',
        'transmit_mode': 'continuous', 'length_mode': 'fixed', 'duration': 1,
        'l2_encap': 'ethernet_ii_vlan', 'rate_pps': data.rate_pps,
        'high_speed_result_analysis': 0, 'mac_src': mac_src, 'mac_dst': mac_dst,
        'port_handle2': data.tgmap[rx_tg]['handle']
    }

    for rule, attributes in rules.items():
        if ("IP_TYPE" in attributes) or ("ETHER_TYPE" in attributes):
            continue
        if match in rule:
            params = {}
            tmp = dict(my_args)
            for key, value in attributes.items():
                params.update(acl_utils.get_args_l3(key, value, attributes, data.rate_pps, data.tg_type))
            tmp.update(params)
            stream = data.tgmap[tx_tg]['tg'].tg_traffic_config(**tmp)
            stream_id = stream['stream_id']
            s = {}
            s[stream_id] = attributes
            s[stream_id]['TABLE'] = rule
            if return_stream:
                return s
            data.tgmap[tx_tg]['streams'].update(s)


def transmit(tg):
    print_log("Transmitting streams")
    data.tgmap[tg]['tg'].tg_traffic_control(action='run', stream_handle=list(data.tgmap[tg]['streams'].keys()),
                                            duration=1)

def verify_acl_hit_counters(dut, table_name, counters_dict, acl_type="ip", **kwargs):
    acl_rule_counters = acl_obj.show_acl_counters(dut, acl_table=table_name, acl_type=acl_type, **kwargs)
    _ = [acl_rule_counter.update({"rule_no": int(re.sub(r"[a-z|A-Z]", "", acl_rule_counter["rulename"])), "access_list_name": acl_rule_counter["tablename"]}) for acl_rule_counter in acl_rule_counters if acl_rule_counter.get("rulename") and acl_rule_counter.get("tablename")]
    st.debug("acl_rule_counters after processing: {}".format(acl_rule_counters))
    if acl_rule_counters:
        for rule_type, rules_list in counters_dict.items():
            for rule_dict in utils.make_list(rules_list):
                entries = utils.filter_and_select(acl_rule_counters, ['packetscnt', 'bytescnt'], rule_dict)
                if entries and isinstance(entries[0], dict) and entries[0].get('packetscnt') and entries[0].get('bytescnt'):
                    if rule_type == 'hit_rules':
                        if int(entries[0]['packetscnt']) < 50:
                            st.error("ACL hit counter not incremented for ACL Rule: {}".format(rule_dict))
                            return False
                    else:
                        if int(entries[0]['packetscnt']) != 0:
                            st.error("ACL hit counter incremented for ACL Rule: {}".format(rule_dict))
                            return False
                else:
                    st.error("Counter entry: {} not found".format(rule_dict))
                    return False
    return True

def verify_packet_count(tx, tx_port, rx, rx_port, table):
    result = True
    tg_tx = data.tgmap[tx]
    tg_rx = data.tgmap[rx]
    exp_ratio = 0
    action = "DROP"
    attr_list = []
    traffic_details = dict()
    action_list = []
    index = 0
    for s_id, attr in tg_tx['streams'].items():
        if table in attr['TABLE']:
            index = index + 1
            if attr["PACKET_ACTION"] == "FORWARD":
                exp_ratio = 1
                action = "FORWARD"
            else:
                exp_ratio = 0
                action = "DROP"
            traffic_details[str(index)] = {
                    'tx_ports': [tx_port],
                    'tx_obj': [tg_tx["tg"]],
                    'exp_ratio': [exp_ratio],
                    'rx_ports': [rx_port],
                    'rx_obj': [tg_rx["tg"]],
                    'stream_list': [[s_id]]
                }
            attr_list.append(attr)
            action_list.append(action)
    result_all = tgapi.validate_tgen_traffic(traffic_details=traffic_details, mode='streamblock',
                                    comp_type='packet_count', return_all=1, delay_factor=1.2)
    for result1, action, attr in zip(result_all[1], action_list, attr_list):
        result = result and result1
        if result1:
            if action == "FORWARD":
                msg = "Traffic successfully forwarded for the rule: {}".format(json.dumps(attr))
                print_log(msg)
            else:
                msg = "Traffic successfully dropped for the rule: {}".format(json.dumps(attr))
                print_log(msg)
        else:
            if action == "FORWARD":
                msg = "Traffic failed to forward for the rule: {}".format(json.dumps(attr))
                print_log(msg)
            else:
                msg = "Traffic failed to drop for the rule: {}".format(json.dumps(attr))
                print_log(msg)
    return result


def initialize_topology():
    print_log("Initializing Topology")
    (tg1, tg2, tg_ph_1, tg_ph_2) = get_handles()
    data.tgmap = {
        "tg1": {
            "tg": tg1,
            "handle": tg_ph_1,
            "streams": {}
        },
        "tg2": {
            "tg": tg2,
            "handle": tg_ph_2,
            "streams": {}
        }
    }
    data.vars = vars


@pytest.fixture(scope="module", autouse=True)
def acl_v4_module_hooks(request):
    # initialize topology
    initialize_topology()
    data.intf_mode = st.get_args("routed_sub_intf")
    st.banner("sub intf_mode is: {}".format(data.intf_mode))
    # apply module configuration
    apply_module_configuration()

    acl_config1 = acl_data.acl_json_config_v4_l3_traffic
    add_port_to_acl_table(acl_config1, 'L3_IPV4_INGRESS', vars.D1T1P1)


    acl_config2 = acl_data.acl_json_config_v6_l3_traffic
    add_port_to_acl_table(acl_config2, 'L3_IPV6_INGRESS', vars.D2T1P1)


    # creating ACL tables and rules
    print_log('Creating ACL tables and rules')
    utils.exec_all(True, [
        utils.ExecAllFunc(acl_obj.apply_acl_config, vars.D1, acl_config1),
        utils.ExecAllFunc(acl_obj.apply_acl_config, vars.D2, acl_config2),
    ])

    # create streams
    data.mac1 = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    data.mac2 = basic_obj.get_ifconfig_ether(vars.D2, vars.D2T1P1)
    print_log('Creating streams')
    create_streams("tg1", "tg2", acl_config1['ACL_RULE'], "L3_IPV4_INGRESS", \
                   mac_src="00:0a:01:00:00:01", mac_dst=data.mac1)
    create_streams("tg1", "tg2", acl_config2['ACL_RULE'], "L3_IPV6_EGRESS", \
                   mac_src="00:0a:01:00:00:01", mac_dst="00:0a:01:00:11:02")
    create_streams("tg2", "tg1", acl_config2['ACL_RULE'], "L3_IPV6_INGRESS", \
                   mac_src="00:0a:01:00:11:02", mac_dst=data.mac2)
    create_streams("tg2", "tg1", acl_config1['ACL_RULE'], "L3_IPV4_EGRESS", \
                   mac_src="00:0a:01:00:11:02", mac_dst="00:0a:01:00:00:01")
    print_log('Completed module configuration')

    st.log("Configuring ipv4 address on TG connected interfaces and portchannels present on both the DUTs")
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.ipv4_address_D1, 24, family="ipv4", config='add')
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2T1P1, data.ipv4_address_D2, 24, family="ipv4", config='add')
    ip_obj.config_ip_addr_interface(vars.D1, data.portChannelName, data.ipv4_portchannel_D1, 24, family="ipv4",
                                    config='add')
    ip_obj.config_ip_addr_interface(vars.D2, data.portChannelName, data.ipv4_portchannel_D2, 24, family="ipv4",
                                    config='add')

    st.log("Configuring ipv6 address on TG connected interfaces and portchannels present on both the DUTs")
    ip_obj.config_ip_addr_interface(vars.D1, vars.D1T1P1, data.ipv6_address_D1, 64, family="ipv6", config='add')
    ip_obj.config_ip_addr_interface(vars.D2, vars.D2T1P1, data.ipv6_address_D2, 64, family="ipv6", config='add')
    ip_obj.config_ip_addr_interface(vars.D1, data.portChannelName, data.ipv6_portchannel_D1, 64, family="ipv6",
                                    config='add')
    ip_obj.config_ip_addr_interface(vars.D2, data.portChannelName, data.ipv6_portchannel_D2, 64, family="ipv6",
                                    config='add')

    st.log("configuring ipv4 static routes on both the DUTs")
    ip_obj.create_static_route(vars.D1, data.ipv4_portchannel_D2, data.ipv4_network_D2, shell="vtysh",
                               family="ipv4")
    ip_obj.create_static_route(vars.D2, data.ipv4_portchannel_D1, data.ipv4_network_D1, shell="vtysh",
                               family="ipv4")

    st.log("configuring ipv6 static routes on both the DUTs")
    ip_obj.create_static_route(vars.D1, data.ipv6_portchannel_D2, data.ipv6_network_D2, shell="vtysh",
                               family="ipv6")
    ip_obj.create_static_route(vars.D2, data.ipv6_portchannel_D1, data.ipv6_network_D1, shell="vtysh",
                               family="ipv6")

    st.log("configuring static arp entries")
    arp_obj.add_static_arp(vars.D1, "1.1.1.2", "00:0a:01:00:00:01", vars.D1T1P1)
    arp_obj.add_static_arp(vars.D2, "2.2.2.2", "00:0a:01:00:11:02", vars.D2T1P1)
    arp_obj.add_static_arp(vars.D2, "2.2.2.4", "00:0a:01:00:11:02", vars.D2T1P1)
    arp_obj.add_static_arp(vars.D1, "1.1.1.4", "00:0a:01:00:00:01", vars.D1T1P1)
    arp_obj.add_static_arp(vars.D2, "2.2.2.5", "00:0a:01:00:11:02", vars.D2T1P1)
    arp_obj.add_static_arp(vars.D1, "1.1.1.5", "00:0a:01:00:00:01", vars.D1T1P1)
    arp_obj.add_static_arp(vars.D2, "2.2.2.6", "00:0a:01:00:11:02", vars.D2T1P1)
    arp_obj.add_static_arp(vars.D1, "1.1.1.6", "00:0a:01:00:00:01", vars.D1T1P1)
    arp_obj.show_arp(vars.D1)
    arp_obj.show_arp(vars.D2)

    st.log("configuring static ndp entries")
    arp_obj.config_static_ndp(vars.D1, "1001::2", "00:0a:01:00:00:01", vars.D1T1P1, operation="add")
    arp_obj.config_static_ndp(vars.D2, "2001::2", "00:0a:01:00:11:02", vars.D2T1P1, operation="add")
    arp_obj.show_ndp(vars.D1)
    arp_obj.show_ndp(vars.D2)

    yield
    clear_module_configuration()


def verify_rule_priority(dut, table_name, acl_type="ip"):
    acl_rule = "PermitAny6" if "IPV4" in table_name else "PermitAny5"
    acl_rule_counters = acl_obj.show_acl_counters(dut, acl_table=table_name, acl_rule=acl_rule, acl_type=acl_type)
    if isinstance(acl_rule_counters, bool):
        print_log("Failed to read ACL counters")
        return False
    if len(acl_rule_counters) == 1:
        packetscnt = acl_rule_counters[0]['packetscnt']
        if not packetscnt or int(packetscnt) != 0:
            print_log("ACL Rule priority test failed")
            return False
    return True


@pytest.mark.acl_test123
@pytest.mark.inventory(feature='Regression', release='Buzznik+')
@pytest.mark.inventory(testcases=['acl_in_ipv4_l3_fwd'])
def test_ft_acl_ingress_ipv4_l3_forwarding():
    '''
    IPv4 Ingress ACL is applied on DUT1 port connected to TG Port#1
    Traffic is sent on TG Port #1
    Traffic is recieved at TG Port #2
    '''
    transmit('tg1')
    result1 = verify_packet_count('tg1', vars.T1D1P1, 'tg2', vars.T1D2P1, "L3_IPV4_INGRESS")
    print_log('Verifing IPv4 Ingress ACL hit counters')
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': i} for i in [1,2,4,5]]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L3_IPV4_INGRESS', 'rule_no': 6}
    result2 = verify_acl_hit_counters(vars.D1, "L3_IPV4_INGRESS", counters_dict)
    result3 = verify_rule_priority(vars.D1, "L3_IPV4_INGRESS")
    acl_utils.report_result(result1 and result2 and result3)


@pytest.mark.acl_test123
@pytest.mark.inventory(feature='Regression', release='Arlo+')
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn093'])
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn096'])
@pytest.mark.inventory(testcases=['FtOpSoQosAclFn098'])
def test_ft_acl_ingress_ipv6_l3_forwarding():
    '''
    IPv6 Ingress ACL is applied on DUT2 port connected to TG Port #2
    Traffic is sent on TG Port #2
    Traffic is recieved at TG Port #1
    '''

    transmit('tg2')
    result1 = verify_packet_count('tg2', vars.T1D2P1, 'tg1', vars.T1D1P1, "L3_IPV6_INGRESS")
    print_log('Verifing IPv6 Ingress ACL hit counters')
    counters_dict = {'hit_rules': [{'access_list_name': 'L3_IPV6_INGRESS', 'rule_no': i} for i in [1, 3, 4]]}
    counters_dict['non_hit_rules'] = {'access_list_name': 'L3_IPV6_INGRESS', 'rule_no': 5}
    result2 = st.poll_wait(verify_acl_hit_counters, 15, vars.D2, "L3_IPV6_INGRESS", counters_dict, acl_type="ipv6")
    result3 = verify_rule_priority(vars.D2, "L3_IPV6_INGRESS", acl_type=data.acl_type)
    acl_utils.report_result(result1 and result2 and result3)

@pytest.fixture(scope="function")
def IpAcl_gnmi_001_fixture(request):
    cli_type = st.get_ui_type(vars.D1)
    yield
    acl_obj.config_access_group(vars.D1, acl_type=data.typev4, table_name=data.create_ipacl,
                               port=vars.D1T1P1, access_group_action='in', cli_type=cli_type, config="no")
    acl_obj.delete_acl_table(vars.D1, acl_type=data.typev4, acl_table_name=[data.create_ipacl])
    acl_obj.config_access_group(vars.D1, acl_type=data.acl_type, table_name=data.create_ipv6acl,
                               port=vars.D1T1P1, access_group_action='in', cli_type=cli_type, config="no")
    acl_obj.delete_acl_table(vars.D1, acl_type=data.acl_type, acl_table_name=[data.create_ipv6acl])

@pytest.mark.inventory(feature='Replace_BasicL3', release='Cyrus4.1.1')
@pytest.mark.inventory(testcases=['BasicL3_Replace_IpAcl_001'])
def test_BasicL3_Replace_IpAcl_001(IpAcl_gnmi_001_fixture):
    '''
        Verify Ip Acl states and functionality by modifying parameters using GNMI Replace.
        This test function will be executed for Gnmi & Rest UI types and
        report unsupported for Klish and Click.

        Approach:
        1. Using CREATE, configure all possible attributes (non-default values)
        2. Using GET, Validate configure and operational state (bgp, mclag session is up etc)
        3. Using REPLACE, replace 1 or 2 attributes,
        4. Using GET, Validate that specified attribute is modified and
        all other remaining is set to default (if it has a default value) or null
        5. Using REPLACE, replace all attributes,
        6. Using GET, Validate configure and operational state (bgp, mclag session is up etc)
        7. Validate traffic
        8. Using UPDATE, set the values used in base_config.
    '''
    tc_list = ['BasicL3_Replace_IpAcl_001']
    st.banner("Testcase: Verify Basic Replace in Ip Acl functionality.\n TCs:{}.".format(tc_list))
    cli_type = st.get_ui_type(vars.D1)
    if cli_type not in utils_obj.get_supported_ui_type_list():
        st.report_unsupported("test_execution_skipped", "TestCase not valid for this UI-Type")
    ##### Create Ip Acl Rule with new set of non-default attribute values ##########################
    st.banner("1.1 Using CREATE, configure all possible attributes (non-default values)",delimiter='=')
    #################################################################################################

    data.create_param_map_1 = {vars.D1: {'Name': data.create_ipacl,
                                         'Type': data.typev4}
                                      }

    result = acl_lib.create_acl(vars.D1, data.create_param_map_1, Operation.CREATE)
    data.create_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,
                                         'Action': data.create_action,
                                         'Sip': data.create_sip,
                                         'Dip': data.create_dip,
                                         'IpProto': data.create_proto,
                                         'Ipv4Dscp': data.create_dscp}
                                       }

    result = acl_lib.acl_rule_change(vars.D1,data.create_param_map_1,data.create_param_map_2,Operation.CREATE)
    if not result:
        fail_msg = 'Ip Acl Rule Create Failed'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Verify Ip Acl Rule Configured and Operational states #####################
    st.banner("1.2 Using GET, Validate configure and operational state", delimiter='=')
    #################################################################################

    data.get_param_map_1 = data.create_param_map_1.copy()
    data.get_param_map_2 = data.create_param_map_2.copy()
    result = acl_lib.acl_rule_verify(vars.D1,data.get_param_map_1,data.get_param_map_2)
    if not result:
        fail_msg = 'Ip Acl Rule Verification after Create Failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Replace Single Ip Acl Rule attribute ##############################
    st.banner("1.3 Using REPLACE, replace 1 or 2 attributes", delimiter='=')
    ########################################################################

    data.repl_param_map_1 = {vars.D1: {'Name': data.create_ipacl,
                                       'Type': data.typev4}
                                    }
    data.repl_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,
                                       'Action': data.repl_action}
                                    }

    result = acl_lib.acl_rule_change(vars.D1,data.repl_param_map_1,data.repl_param_map_2,Operation.REPLACE)

    ##### Verify specified Ip Acl Rule attribute is modified and remaining set to default ##########
    st.banner("1.4 Using GET, Validate that specified attribute is modified and all other remaining "\
              "is set to default (if it has a default value) or null", delimiter='=')
    #################################################################################################

    data.get_def_param_map_1 = {vars.D1: {'Name': data.create_ipacl,
                                          'Type': data.typev4}
                                        }
    data.get_def_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,
                                          'Action': data.repl_action,
                                          'Sip': data.default_ip,
                                          'Dip': data.default_ip}
                                        }

    result = acl_lib.acl_rule_verify(vars.D1, data.get_def_param_map_1, data.get_def_param_map_2)
    if not result:
        fail_msg = 'Ip Acl Rule Default attributes after Single Replace Failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Replace ALL Ip Acl Rule attribute values ###################
    st.banner("1.5 Using REPLACE, replace all attributes", delimiter='=')
    ###################################################################
    data.repl_param_map_1 = {vars.D1: {'Name': data.create_ipacl,
                                       'Type': data.typev4}
                                    }
    data.repl_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,
                                       'Action': data.repl_action,
                                       'Sip': data.repl_sip,
                                       'Dip': data.repl_dip,
                                       'IpProto': data.repl_proto,
                                       'Ipv4Dscp': data.repl_dscp}
                                    }

    result = acl_lib.acl_rule_change(vars.D1, data.repl_param_map_1, data.repl_param_map_2, Operation.REPLACE)
    if not result:
        fail_msg = 'Ip Acl Rule Config with Replace All Failed'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Verify configure and operational state ######################################
    st.banner("1.6 Using GET, Validate configure and operational state", delimiter='=')
    ###################################################################################

    data.get_param_map_1 = data.repl_param_map_1.copy()
    data.get_param_map_2 = data.repl_param_map_2.copy()
    result = acl_lib.acl_rule_verify(vars.D1,data.get_param_map_1,data.get_param_map_2)
    if not result:
        fail_msg = 'Ip Acl Rule attributes validation afer Replace All Failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    acl_obj.config_access_group(vars.D1, acl_type=data.typev4, table_name=data.create_ipacl,
                               port=vars.D1T1P1, access_group_action='in', cli_type=cli_type)

    ####### Create Stream ##########
    data.dst_mac = basic_obj.get_ifconfig_ether(vars.D1, vars.D1T1P1)
    stream = create_streams("tg1", "tg2", acl_rules_data.ip_acl_rule, data.create_ipacl,
                mac_src=data.src_mac, mac_dst=data.dst_mac, return_stream=True)

    ####### Tramsmit Streams #######
    print_log("Transmitting streams")
    data.tgmap['tg1']['tg'].tg_traffic_control(action='run', stream_handle = stream, duration=1)
    data.tgmap['tg1']['tg'].tg_traffic_control(action='stop', stream_handle = stream)

    ####### Verify Counters #########
    counters_dict = {'hit_rules': {'access_list_name': data.create_ipacl, 'rule_no': data.create_seq}}
    result = st.poll_wait(verify_acl_hit_counters, 10, vars.D1, data.create_ipacl, counters_dict, acl_type=data.typev4)
    if not result:
        fail_msg = 'Ip Acl Rule counters update verification failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    #################
    ##### IPV6 ######
    #################

    ##### Create Ipv6 Acl Rule with new set of non-default attribute values ##########################
    st.banner("2.1 Using CREATE, configure all possible attributes (non-default values)",delimiter='=')
    #################################################################################################

    data.create_param_map_1 = {vars.D1: {'Name': data.create_ipv6acl,
                                         'Type': data.acl_type}
                                      }

    result = acl_lib.create_acl(vars.D1, data.create_param_map_1, Operation.CREATE)
    data.create_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,
                                         'Action': data.create_action,
                                         'Sipv6': data.create_sipv6,
                                         'Dipv6': data.create_dipv6,
                                         'Ipv6Proto': data.create_proto,
                                         'Ipv6Dscp': data.create_dscp}
                                       }

    result = acl_lib.acl_rule_change(vars.D1,data.create_param_map_1,data.create_param_map_2,Operation.CREATE)
    if not result:
        fail_msg = 'Ipv6 Acl Rule Create Failed'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Verify Ipv6 Acl Rule Configured and Operational states #####################
    st.banner("2.2 Using GET, Validate configure and operational state", delimiter='=')
    #################################################################################

    data.get_param_map_1 = data.create_param_map_1.copy()
    data.get_param_map_2 = data.create_param_map_2.copy()
    result = acl_lib.acl_rule_verify(vars.D1,data.get_param_map_1,data.get_param_map_2)
    if not result:
        fail_msg = 'Ipv6 Acl Rule Verification after Create Failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Replace Single Ipv6 Acl Rule attribute ##############################
    st.banner("2.3 Using REPLACE, replace 1 or 2 attributes", delimiter='=')
    ########################################################################

    data.repl_param_map_1 = {vars.D1: {'Name': data.create_ipv6acl,
                                       'Type': data.acl_type}
                                    }
    data.repl_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,
                                       'Action': data.repl_action}
                                    }

    result = acl_lib.acl_rule_change(vars.D1,data.repl_param_map_1,data.repl_param_map_2,Operation.REPLACE)

    ##### Verify specified Ipv6 Acl Rule attribute is modified and remaining set to default ##########
    st.banner("2.4 Using GET, Validate that specified attribute is modified and all other remaining "\
              "is set to default (if it has a default value) or null", delimiter='=')
    #################################################################################################

    data.get_def_param_map_1 = {vars.D1: {'Name': data.create_ipv6acl,
                                          'Type': data.acl_type}
                                        }
    data.get_def_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,
                                          'Action': data.repl_action,
                                          'Sipv6': data.default_ip,
                                          'Dipv6': data.default_ip}
                                        }

    result = acl_lib.acl_rule_verify(vars.D1, data.get_def_param_map_1, data.get_def_param_map_2)
    if not result:
        fail_msg = 'Ipv6 Acl Rule Default attributes after Single Replace Failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Replace ALL Ipv6 Acl Rule attribute values ###################
    st.banner("2.5 Using REPLACE, replace all attributes", delimiter='=')
    ###################################################################

    data.repl_param_map_1 = {vars.D1: {'Name': data.create_ipv6acl,
                                       'Type': data.acl_type}
                                    }
    data.repl_param_map_2 = {vars.D1: {'SeqNum': data.create_seq,
                                       'Action': data.repl_action,
                                       'Sipv6': data.repl_sipv6,
                                       'Dipv6': data.repl_dipv6,
                                       'Ipv6Proto': data.repl_proto,
                                       'Ipv6Dscp': data.repl_dscp}
                                    }

    result = acl_lib.acl_rule_change(vars.D1, data.repl_param_map_1, data.repl_param_map_2, Operation.REPLACE)
    if not result:
        fail_msg = 'Ipv6 Acl Rule Config with Replace All Failed'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    ##### Verify configure and operational state ######################################
    st.banner("2.6 Using GET, Validate configure and operational state", delimiter='=')
    ###################################################################################

    data.get_param_map_1 = data.repl_param_map_1.copy()
    data.get_param_map_2 = data.repl_param_map_2.copy()
    result = acl_lib.acl_rule_verify(vars.D1,data.get_param_map_1,data.get_param_map_2)
    if not result:
        fail_msg = 'Ipv6 Acl Rule attributes validation afer Replace All Failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    acl_obj.config_access_group(vars.D1, acl_type=data.acl_type, table_name=data.create_ipv6acl,
                               port=vars.D1T1P1, access_group_action='in', cli_type=cli_type)

    ####### Create Stream ##########
    stream = create_streams("tg1", "tg2", acl_rules_data.ipv6_acl_rule, data.create_ipv6acl,
                mac_src=data.src_mac, mac_dst=data.dst_mac, return_stream=True)

    ####### Tramsmit Streams #######
    print_log("Transmitting streams")
    data.tgmap['tg1']['tg'].tg_traffic_control(action='run', stream_handle = stream, duration=1)
    data.tgmap['tg1']['tg'].tg_traffic_control(action='stop', stream_handle = stream)

    ####### Verify Counters #########
    counters_dict = {'hit_rules': {'access_list_name': data.create_ipv6acl, 'rule_no': data.create_seq}}
    result = st.poll_wait(verify_acl_hit_counters, 10, vars.D1, data.create_ipv6acl, counters_dict, acl_type=data.acl_type)
    if not result:
        fail_msg = 'Ipv6 Acl Rule counters update verification failed:'
        st.banner("test_step_failed:{}".format(fail_msg))
        st.report_fail('test_case_failure_message', fail_msg.strip(':'))

    st.report_pass("test_case_passed")
